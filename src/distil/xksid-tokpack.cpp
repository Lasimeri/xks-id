// xksid-tokpack: offline companion of xksid-distil. No GPU.
//
//   pack   MODEL OUT      write the tokenizer bundle xksid reads
//   tokens MODEL FILE...  print llama.cpp's token ids of each file, one line per
//                         file: the reference the C tokenizer is tested against
//
// Bundle (little endian):
//   "XKSIDTOK", u32 version = 2, u32 n_vocab, u32 n_merges, u32 n_class
//   u8 class[n_class]   per code point: bit 0 letter, bit 1 number, bit 2 whitespace,
//                       taken from llama.cpp's own Unicode tables
//   u8 type[n_vocab]    token type of the model: 1 normal, 3 control, 4 user defined, 5 unused
//   n_vocab  x { u16 length, bytes }                 token text, byte-level form
//   n_merges x { u16 left, u16 right, bytes, bytes } merge pairs in rank order
// Only byte-level BPE vocabularies ("gpt2") are packed.

#include "llama.h"
#include "common.h"
#include "gguf.h"
#include "unicode.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

[[noreturn]] void fail(const std::string & msg) {
    std::fprintf(stderr, "xksid-tokpack: %s\n", msg.c_str());
    std::exit(1);
}

void put_u16(std::FILE * f, size_t v) {
    if (v > 0xFFFF) {
        fail("a token text is longer than 65535 bytes");
    }
    const unsigned char b[2] = {static_cast<unsigned char>(v & 0xFF), static_cast<unsigned char>(v >> 8)};
    std::fwrite(b, 1, 2, f);
}

void put_u32(std::FILE * f, uint32_t v) {
    const unsigned char b[4] = {static_cast<unsigned char>(v), static_cast<unsigned char>(v >> 8),
                                static_cast<unsigned char>(v >> 16), static_cast<unsigned char>(v >> 24)};
    std::fwrite(b, 1, 4, f);
}

int64_t key(const gguf_context * g, const char * name) {
    const int64_t k = gguf_find_key(g, name);
    if (k < 0) {
        fail(std::string("the model has no ") + name);
    }
    return k;
}

int pack(const char * model, const char * out) {
    gguf_init_params params;
    params.no_alloc = true;
    params.ctx      = nullptr;
    gguf_context * g = gguf_init_from_file(model, params);
    if (g == nullptr) {
        fail(std::string("cannot read ") + model);
    }
    if (std::string(gguf_get_val_str(g, key(g, "tokenizer.ggml.model"))) != "gpt2") {
        fail("only byte-level BPE vocabularies (gpt2) are supported");
    }
    const int64_t kt = key(g, "tokenizer.ggml.tokens");
    const int64_t km = key(g, "tokenizer.ggml.merges");
    const size_t  nt = gguf_get_arr_n(g, kt);
    const size_t  nm = gguf_get_arr_n(g, km);
    const uint32_t n_class = 0x110000;

    std::FILE * f = std::fopen(out, "wb");
    if (f == nullptr) {
        fail(std::string("cannot write ") + out);
    }
    std::fwrite("XKSIDTOK", 1, 8, f);
    put_u32(f, 2);
    put_u32(f, static_cast<uint32_t>(nt));
    put_u32(f, static_cast<uint32_t>(nm));
    put_u32(f, n_class);

    std::vector<unsigned char> cls(n_class);
    for (uint32_t cp = 0; cp < n_class; cp++) {
        const unicode_cpt_flags fl = unicode_cpt_flags_from_cpt(cp);
        cls[cp] = static_cast<unsigned char>((fl.is_letter ? 1 : 0) | (fl.is_number ? 2 : 0) | (fl.is_whitespace ? 4 : 0));
    }
    std::fwrite(cls.data(), 1, cls.size(), f);

    const int64_t ky = key(g, "tokenizer.ggml.token_type");
    if (gguf_get_arr_n(g, ky) != nt) {
        fail("token types and tokens differ in count");
    }
    const int32_t * types = static_cast<const int32_t *>(gguf_get_arr_data(g, ky));
    for (size_t i = 0; i < nt; i++) {
        std::fputc(types[i] & 0xFF, f);
    }

    for (size_t i = 0; i < nt; i++) {
        const std::string t = gguf_get_arr_str(g, kt, i);
        put_u16(f, t.size());
        std::fwrite(t.data(), 1, t.size(), f);
    }
    for (size_t i = 0; i < nm; i++) {
        const std::string m  = gguf_get_arr_str(g, km, i);
        const size_t      sp = m.find(' ', 1);
        if (sp == std::string::npos) {
            fail("a merge has no separator");
        }
        put_u16(f, sp);
        put_u16(f, m.size() - sp - 1);
        std::fwrite(m.data(), 1, sp, f);
        std::fwrite(m.data() + sp + 1, 1, m.size() - sp - 1, f);
    }
    const long bytes = std::ftell(f);
    if (std::fclose(f) != 0) {
        fail(std::string("cannot write ") + out);
    }
    std::printf("%s: %zu tokens, %zu merges, %u classes, %ld bytes\n", out, nt, nm, n_class, bytes);
    gguf_free(g);
    return 0;
}

int tokens(const char * model_path, int n, char ** files) {
    llama_backend_init();
    llama_log_set([](enum ggml_log_level, const char *, void *) {}, nullptr);
    llama_model_params mp = llama_model_default_params();
    mp.vocab_only = true;
    llama_model * model = llama_model_load_from_file(model_path, mp);
    if (model == nullptr) {
        fail(std::string("cannot load ") + model_path);
    }
    const llama_vocab * vocab = llama_model_get_vocab(model);
    for (int i = 0; i < n; i++) {
        std::ifstream in(files[i], std::ios::binary);
        if (!in) {
            fail(std::string("cannot read ") + files[i]);
        }
        std::ostringstream buf;
        buf << in.rdbuf();
        std::string line;
        for (const llama_token t : common_tokenize(vocab, buf.str(), false, false)) {
            line += std::to_string(t);
            line += ' ';
        }
        std::printf("%s\n", line.c_str());
    }
    llama_model_free(model);
    llama_backend_free();
    return 0;
}

} // namespace

int main(int argc, char ** argv) {
    const std::string mode = argc > 1 ? argv[1] : "";
    if (mode == "pack" && argc == 4) {
        return pack(argv[2], argv[3]);
    }
    if (mode == "tokens" && argc >= 4) {
        return tokens(argv[2], argc - 3, argv + 3);
    }
    std::fprintf(stderr, "usage: xksid-tokpack pack MODEL OUT\n       xksid-tokpack tokens MODEL FILE...\n");
    return 2;
}
