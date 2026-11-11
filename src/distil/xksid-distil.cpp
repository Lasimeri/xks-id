// xksid-distil: offline distiller for layer L6 of xks-id.
//
// Runs a d1 decision model (type lfm3-d1, GGUF) through llama.cpp and records,
// for one fixed yes/no question, the decision vector of a state: the final
// hidden state at the last prompt token. The model reads its own answer from
// that vector, so it is the pre-head representation of the decision. Nothing
// in this file runs at detection time.
//
// The prompt and the readout follow tools/server/server-decision.cpp of
// llama.cpp: the "systemone" template stored in the model renders the
// question, the answer is the logits of the label tokens at the last prompt
// token, the maximum inside each label group (yes/Yes/YES and no/No/NO), and
// a two-way softmax at the temperature stored in the model metadata.
// Not reproduced: the pass that breaks the spellings of control tokens inside
// the input text. States and questions given to this tool must not contain a
// control-token spelling.
//
// Modes:
//   info  MODEL QUESTION                  model facts and the rendered prompt
//   score MODEL QUESTION STATES           P(yes) per line of STATES, both paths
//   table MODEL QUESTION OUT FIRST LAST [WORKERS [CTX]]
//                                         decision vectors of tokens [FIRST, LAST),
//                                         WORKERS contexts on the one loaded model
//   label MODEL QUESTION IN OUT WIDTH [WORKERS]
//                                         the model's yes and no logits for windows of
//                                         WIDTH token ids read from IN: the labels the
//                                         head is fitted to (xksid-fit)
//
// QUESTION is a text file holding the instructions of the yes/no question.
// The table mode writes OUT.vec.f32 (n_vocab rows of n_embd floats, row t at
// offset t * n_embd * 4), OUT.logit.f32 (per token: yes logit, no logit) and
// OUT.meta. A skipped token keeps a zero row and NaN logits.

#include "llama.h"
#include "common.h"
#include "chat.h"
#include "json.h"
#include "jinja/runtime.h"
#include "jinja/value.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace {

[[noreturn]] void fail(const std::string & msg) {
    std::fprintf(stderr, "xksid-distil: %s\n", msg.c_str());
    std::exit(1);
}

void log_quiet(enum ggml_log_level level, const char * text, void *) {
    if (level == GGML_LOG_LEVEL_ERROR || level == GGML_LOG_LEVEL_WARN) {
        std::fputs(text, stderr);
    }
}

std::string read_file(const std::string & path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        fail("cannot read " + path);
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

std::string trim_newlines(std::string text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
    }
    return text;
}

// JSON string literal of UTF-8 text
std::string json_quote(const std::string & text) {
    std::string out = "\"";
    for (const char ch : text) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c == '"' || c == '\\') {
            out += '\\';
            out += ch;
        } else if (c < 0x20) {
            char esc[8];
            std::snprintf(esc, sizeof(esc), "\\u%04x", static_cast<unsigned>(c));
            out += esc;
        } else {
            out += ch;
        }
    }
    return out + "\"";
}

struct forward_result {
    float yes = 0.0f; // maximum logit of the yes group
    float no  = 0.0f; // maximum logit of the no group
};

struct distiller {
    llama_model *       model = nullptr;
    llama_context *     ctx   = nullptr;
    const llama_vocab * vocab = nullptr;
    llama_batch         batch = {};

    std::unique_ptr<common_chat_template> tmpl;
    std::string arch;
    std::string question;
    float       temperature = 1.0f;
    int32_t     n_embd      = 0;
    int32_t     n_vocab     = 0;
    int32_t     n_ctx       = 4096; // tokens one context reads in one batch

    std::vector<llama_token> yes;   // label tokens of the option "true"
    std::vector<llama_token> no;     // label tokens of the option "false"
    std::vector<llama_token> prefix; // prompt tokens before the state
    std::vector<llama_token> suffix; // prompt tokens after the state

    std::string meta(const std::string & key) const {
        char buf[256];
        const int32_t n = llama_model_meta_val_str(model, key.c_str(), buf, sizeof(buf));
        return n < 0 ? std::string() : std::string(buf);
    }

    std::vector<llama_token> single_tokens(const std::vector<std::string> & forms) const {
        std::vector<llama_token> out;
        for (const auto & form : forms) {
            const auto toks = common_tokenize(vocab, form, false, false);
            if (toks.size() == 1 && std::find(out.begin(), out.end(), toks[0]) == out.end()) {
                out.push_back(toks[0]);
            }
        }
        return out;
    }

    // the prompt of the question over this state, as the server renders it
    std::string render(const std::string & state) const {
        const std::string text =
            "{\"id\":\"injection\",\"type\":\"noul\",\"instructions\":" + json_quote(question) +
            ",\"state\":" + json_quote(state) +
            ",\"options\":[{\"key\":\"true\",\"description\":null,\"label\":\"true\"},"
            "{\"key\":\"false\",\"description\":null,\"label\":\"false\"}],\"images\":[]}";
        const common_json inp = common_json::parse(text);

        jinja::context jctx(tmpl->src);
        jinja::global_from_json(jctx, inp, false);
        jinja::runtime runtime(jctx);
        const jinja::value results = runtime.execute(tmpl->prog);
        return jinja::runtime::gather_string_parts(results)->as_string().str();
    }

    std::vector<llama_token> tokenize_prompt(const std::string & prompt) const {
        return common_tokenize(vocab, prompt, false, true);
    }

    // every context of a run has the same parameters, so every row comes from the same configuration
    llama_context * new_context() const {
        llama_context_params cp = llama_context_default_params();
        cp.n_ctx           = static_cast<uint32_t>(n_ctx);
        cp.n_batch         = static_cast<uint32_t>(n_ctx);
        cp.n_ubatch        = static_cast<uint32_t>(n_ctx);
        cp.embeddings      = true;
        cp.pooling_type    = LLAMA_POOLING_TYPE_NONE;
        cp.n_threads       = 8;
        cp.n_threads_batch = 8;
        llama_context * c = llama_init_from_model(model, cp);
        if (c == nullptr) {
            fail("cannot create a context");
        }
        return c;
    }

    void load(const std::string & model_path, const std::string & question_path) {
        llama_backend_init();
        llama_log_set(log_quiet, nullptr);

        llama_model_params mp = llama_model_default_params();
        mp.n_gpu_layers = 999;
        mp.load_mode    = LLAMA_LOAD_MODE_NONE; // read the weights, no memory map
        model = llama_model_load_from_file(model_path.c_str(), mp);
        if (model == nullptr) {
            fail("cannot load " + model_path);
        }
        vocab = llama_model_get_vocab(model);

        arch = meta("general.architecture");
        const std::string type = meta(arch + ".decision.type");
        if (type != "lfm3-d1") {
            fail("decision type is \"" + type + "\", this tool reads lfm3-d1 only");
        }

        const char * tmpl_src = llama_model_chat_template(model, "systemone");
        if (tmpl_src == nullptr) {
            fail("the model has no \"systemone\" template");
        }
        tmpl = std::make_unique<common_chat_template>(tmpl_src, "", "");

        for (const char * name : {".decision.temperature.noul.2", ".decision.temperature.noul"}) {
            const std::string val = meta(arch + name);
            if (!val.empty()) {
                temperature = std::strtof(val.c_str(), nullptr);
                break;
            }
        }
        if (!(temperature > 0.0f)) {
            fail("invalid decision temperature");
        }

        yes = single_tokens({"yes", "Yes", "YES"});
        no  = single_tokens({"no", "No", "NO"});
        if (yes.empty() || no.empty()) {
            fail("a yes/no label is not a single token");
        }

        ctx = new_context();

        n_embd = llama_model_n_embd_out(model);
        if (n_embd <= 0) {
            n_embd = llama_model_n_embd(model);
        }
        n_vocab = llama_vocab_n_tokens(vocab);
        batch   = llama_batch_init(n_ctx, 0, 1);

        question = trim_newlines(read_file(question_path));
        if (question.empty()) {
            fail("the question is empty");
        }

        // the tokens around the state: common head and tail of two prompts with different states
        const auto a = tokenize_prompt(render("alpha"));
        const auto b = tokenize_prompt(render("omega 7"));
        size_t np = 0;
        while (np < a.size() && np < b.size() && a[np] == b[np]) {
            np++;
        }
        size_t ns = 0;
        while (ns < a.size() - np && ns < b.size() - np && a[a.size() - 1 - ns] == b[b.size() - 1 - ns]) {
            ns++;
        }
        prefix.assign(a.begin(), a.begin() + static_cast<std::ptrdiff_t>(np));
        suffix.assign(a.end() - static_cast<std::ptrdiff_t>(ns), a.end());
        if (suffix.empty()) {
            fail("the prompt ends with the state, there is no fixed last token to read");
        }
    }

    forward_result forward(const std::vector<llama_token> & tokens, float * vec) {
        return forward(ctx, batch, tokens, vec);
    }

    // one forward pass over one prompt in the context c; vec receives n_embd floats if not null
    forward_result forward(llama_context * c, llama_batch & b, const std::vector<llama_token> & tokens, float * vec) const {
        const int32_t n = static_cast<int32_t>(tokens.size());
        if (n <= 0 || n > n_ctx) {
            fail("prompt of " + std::to_string(n) + " tokens does not fit one batch of " + std::to_string(n_ctx));
        }
        b.n_tokens = n;
        for (int32_t i = 0; i < n; i++) {
            b.token[i]     = tokens[static_cast<size_t>(i)];
            b.pos[i]       = i;
            b.n_seq_id[i]  = 1;
            b.seq_id[i][0] = 0;
            b.logits[i]    = i == n - 1;
        }
        const llama_memory_t mem = llama_get_memory(c);
        if (mem != nullptr) {
            llama_memory_clear(mem, true);
        }
        if (llama_decode(c, b) != 0) {
            fail("llama_decode failed");
        }
        const float * logits = llama_get_logits_ith(c, -1);
        const float * embd   = llama_get_embeddings_ith(c, -1);
        if (logits == nullptr || embd == nullptr) {
            fail("the context returned no logits or no embeddings");
        }
        forward_result res;
        res.yes = -std::numeric_limits<float>::infinity();
        res.no  = -std::numeric_limits<float>::infinity();
        for (const llama_token t : yes) {
            res.yes = std::max(res.yes, logits[t]);
        }
        for (const llama_token t : no) {
            res.no = std::max(res.no, logits[t]);
        }
        if (vec != nullptr) {
            std::memcpy(vec, embd, static_cast<size_t>(n_embd) * sizeof(float));
        }
        return res;
    }

    double p_yes(const forward_result & r) const {
        return 1.0 / (1.0 + std::exp((static_cast<double>(r.no) - static_cast<double>(r.yes)) / static_cast<double>(temperature)));
    }

    std::vector<llama_token> spliced(const std::vector<llama_token> & state) const {
        std::vector<llama_token> out = prefix;
        out.insert(out.end(), state.begin(), state.end());
        out.insert(out.end(), suffix.begin(), suffix.end());
        return out;
    }

    void close() {
        llama_batch_free(batch);
        llama_free(ctx);
        llama_model_free(model);
        llama_backend_free();
    }
};

std::string ids(const std::vector<llama_token> & toks) {
    std::string out;
    for (const llama_token t : toks) {
        out += (out.empty() ? "" : " ") + std::to_string(t);
    }
    return out;
}

void print_facts(const distiller & d, std::FILE * out) {
    std::fprintf(out, "architecture   %s\n", d.arch.c_str());
    std::fprintf(out, "decision type  %s\n", d.meta(d.arch + ".decision.type").c_str());
    std::fprintf(out, "n_vocab        %d\n", d.n_vocab);
    std::fprintf(out, "n_embd         %d\n", d.n_embd);
    std::fprintf(out, "temperature    %.9g\n", static_cast<double>(d.temperature));
    std::fprintf(out, "yes tokens     %s\n", ids(d.yes).c_str());
    std::fprintf(out, "no tokens      %s\n", ids(d.no).c_str());
    std::fprintf(out, "prefix tokens  %zu: %s\n", d.prefix.size(), ids(d.prefix).c_str());
    std::fprintf(out, "suffix tokens  %zu: %s\n", d.suffix.size(), ids(d.suffix).c_str());
    std::fprintf(out, "question       %s\n", d.question.c_str());
}

int mode_info(distiller & d) {
    print_facts(d, stdout);
    std::printf("---- prompt rendered for the state \"alpha\"\n%s\n---- end\n", d.render("alpha").c_str());
    return 0;
}

int mode_score(distiller & d, const std::string & states_path) {
    std::ifstream in(states_path);
    if (!in) {
        fail("cannot read " + states_path);
    }
    std::printf("n_full\tn_splice\tsame\tyes\tno\tp_full\tp_splice\tstate\n");
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        const auto full   = d.tokenize_prompt(d.render(line));
        const auto splice = d.spliced(common_tokenize(d.vocab, line, false, false));
        const forward_result rf = d.forward(full, nullptr);
        const forward_result rs = d.forward(splice, nullptr);
        std::printf("%zu\t%zu\t%d\t%.6f\t%.6f\t%.9f\t%.9f\t%s\n",
                    full.size(), splice.size(), full == splice ? 1 : 0,
                    static_cast<double>(rf.yes), static_cast<double>(rf.no), d.p_yes(rf), d.p_yes(rs), line.c_str());
    }
    return 0;
}

void pwrite_all(int fd, const void * buf, size_t len, off_t off, const std::string & name) {
    const char * p = static_cast<const char *>(buf);
    while (len > 0) {
        const ssize_t n = pwrite(fd, p, len, off);
        if (n <= 0) {
            fail("write failed on " + name);
        }
        p   += n;
        len -= static_cast<size_t>(n);
        off += n;
    }
}

int mode_table(distiller & d, const std::string & out, int32_t first, int32_t last, int32_t workers) {
    if (first < 0 || last > d.n_vocab || first >= last) {
        fail("token range must lie inside [0, " + std::to_string(d.n_vocab) + ")");
    }
    if (workers < 1 || workers > 16) {
        fail("workers must be 1 to 16");
    }
    const std::string vec_path   = out + ".vec.f32";
    const std::string logit_path = out + ".logit.f32";
    // a run that starts at token 0 starts from empty files: no row of an earlier run survives
    const int flags    = O_RDWR | O_CREAT | (first == 0 ? O_TRUNC : 0);
    const int fd_vec   = open(vec_path.c_str(), flags, 0644);
    const int fd_logit = open(logit_path.c_str(), flags, 0644);
    if (fd_vec < 0 || fd_logit < 0) {
        fail("cannot open the output files under " + out);
    }
    const size_t row_bytes = static_cast<size_t>(d.n_embd) * sizeof(float);
    if (ftruncate(fd_vec, static_cast<off_t>(row_bytes) * d.n_vocab) != 0 ||
        ftruncate(fd_logit, static_cast<off_t>(2 * sizeof(float)) * d.n_vocab) != 0) {
        fail("cannot size the output files");
    }

    const float nan = std::numeric_limits<float>::quiet_NaN();
    std::atomic<int32_t> next{first};
    std::atomic<int32_t> a_done{0};
    std::atomic<int32_t> a_skip{0};
    const auto t0 = std::chrono::steady_clock::now();

    // Token ids are handed out in ascending order. A row depends on its own prompt only and is
    // written at the offset of its token, so the files do not depend on the number of workers.
    const auto work = [&](llama_context * c, llama_batch * b) {
        std::vector<float> row(static_cast<size_t>(d.n_embd));
        for (;;) {
            const int32_t t = next.fetch_add(1);
            if (t >= last) {
                return;
            }
            float logit[2] = {nan, nan};
            const uint32_t attr = static_cast<uint32_t>(llama_vocab_get_attr(d.vocab, t));
            if (attr & (LLAMA_TOKEN_ATTR_CONTROL | LLAMA_TOKEN_ATTR_UNUSED | LLAMA_TOKEN_ATTR_UNKNOWN)) {
                std::fill(row.begin(), row.end(), 0.0f);
                a_skip.fetch_add(1);
            } else {
                const forward_result r = d.forward(c, *b, d.spliced({t}), row.data());
                logit[0] = r.yes;
                logit[1] = r.no;
                a_done.fetch_add(1);
            }
            pwrite_all(fd_vec, row.data(), row_bytes, static_cast<off_t>(row_bytes) * t, vec_path);
            pwrite_all(fd_logit, logit, sizeof(logit), static_cast<off_t>(sizeof(logit)) * t, logit_path);

            if ((t - first + 1) % 1000 == 0 || t == last - 1) {
                const double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                const int32_t nd = a_done.load();
                std::fprintf(stderr, "token %d of [%d, %d)  passes %d  skipped %d  %.1f s  %.2f passes/s\n",
                             t + 1, first, last, nd, a_skip.load(), sec, sec > 0.0 ? nd / sec : 0.0);
            }
        }
    };

    const size_t n_workers = static_cast<size_t>(workers);
    std::vector<llama_context *> ctxs    = {d.ctx};
    std::vector<llama_batch>     batches = {d.batch};
    for (size_t w = 1; w < n_workers; w++) {
        ctxs.push_back(d.new_context());
        batches.push_back(llama_batch_init(d.n_ctx, 0, 1));
    }
    std::vector<std::thread> threads;
    for (size_t w = 1; w < n_workers; w++) {
        threads.emplace_back(work, ctxs[w], &batches[w]);
    }
    work(ctxs[0], &batches[0]);
    for (auto & th : threads) {
        th.join();
    }
    for (size_t w = 1; w < n_workers; w++) {
        llama_batch_free(batches[w]);
        llama_free(ctxs[w]);
    }
    const int32_t n_done = a_done.load();
    const int32_t n_skip = a_skip.load();
    if (fsync(fd_vec) != 0 || fsync(fd_logit) != 0) {
        fail("fsync failed");
    }
    close(fd_vec);
    close(fd_logit);

    const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::FILE * meta = std::fopen((out + ".meta").c_str(), "a");
    if (meta == nullptr) {
        fail("cannot write " + out + ".meta");
    }
    print_facts(d, meta);
    std::fprintf(meta, "prompt tokens  %zu per pass\n", d.prefix.size() + 1 + d.suffix.size());
    std::fprintf(meta, "workers        %d contexts of %d tokens on one model\n", workers, d.n_ctx);
    std::fprintf(meta, "range          [%d, %d)  passes %d  skipped %d  %.3f s  %.3f passes/s\n\n",
                 first, last, n_done, n_skip, s, s > 0.0 ? n_done / s : 0.0);
    std::fclose(meta);
    std::printf("range [%d, %d)  passes %d  skipped %d  %.3f s  %.3f passes/s\n",
                first, last, n_done, n_skip, s, s > 0.0 ? n_done / s : 0.0);
    return 0;
}

// The model's yes and no logits for windows of token ids: IN holds int32 ids, WIDTH per
// window; OUT receives two floats per window. Each window is placed where a state goes.
int mode_label(distiller & d, const std::string & in_path, const std::string & out_path, int32_t width, int32_t workers) {
    if (width < 1 || width > d.n_ctx - 128 || workers < 1 || workers > 16) {
        fail("WIDTH or WORKERS out of range");
    }
    const std::string raw = read_file(in_path);
    const size_t n = raw.size() / (static_cast<size_t>(width) * sizeof(int32_t));
    std::vector<int32_t> ids(n * static_cast<size_t>(width));
    std::memcpy(ids.data(), raw.data(), ids.size() * sizeof(int32_t));
    for (const int32_t id : ids) {
        if (id < 0 || id >= d.n_vocab) {
            fail("a token id is outside the vocabulary");
        }
    }
    std::vector<float> out(2 * n);
    std::atomic<size_t> next{0};
    const auto t0 = std::chrono::steady_clock::now();
    const auto work = [&](llama_context * c, llama_batch * b) {
        for (;;) {
            const size_t i = next.fetch_add(1);
            if (i >= n) {
                return;
            }
            const auto first = ids.begin() + static_cast<std::ptrdiff_t>(i * static_cast<size_t>(width));
            const std::vector<llama_token> state(first, first + width);
            const forward_result r = d.forward(c, *b, d.spliced(state), nullptr);
            out[2 * i]     = r.yes;
            out[2 * i + 1] = r.no;
            if ((i + 1) % 1000 == 0) {
                const double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                std::fprintf(stderr, "window %zu of %zu  %.1f s  %.2f passes/s\n", i + 1, n, sec, static_cast<double>(i + 1) / sec);
            }
        }
    };
    const size_t n_workers = static_cast<size_t>(workers);
    std::vector<llama_context *> ctxs    = {d.ctx};
    std::vector<llama_batch>     batches = {d.batch};
    for (size_t w = 1; w < n_workers; w++) {
        ctxs.push_back(d.new_context());
        batches.push_back(llama_batch_init(d.n_ctx, 0, 1));
    }
    std::vector<std::thread> threads;
    for (size_t w = 1; w < n_workers; w++) {
        threads.emplace_back(work, ctxs[w], &batches[w]);
    }
    work(ctxs[0], &batches[0]);
    for (auto & th : threads) {
        th.join();
    }
    for (size_t w = 1; w < n_workers; w++) {
        llama_batch_free(batches[w]);
        llama_free(ctxs[w]);
    }
    std::ofstream f(out_path, std::ios::binary);
    f.write(reinterpret_cast<const char *>(out.data()), static_cast<std::streamsize>(out.size() * sizeof(float)));
    if (!f) {
        fail("cannot write " + out_path);
    }
    const double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("%zu windows of %d tokens  %.3f s  %.3f passes/s  temperature %.9g\n", n, width, sec, static_cast<double>(n) / sec,
                static_cast<double>(d.temperature));
    return 0;
}

} // namespace

int main(int argc, char ** argv) {
    const std::string mode = argc > 1 ? argv[1] : "";
    if (mode == "label" && (argc == 7 || argc == 8)) {
        distiller d;
        d.load(argv[2], argv[3]);
        const int rc = mode_label(d, argv[4], argv[5], std::atoi(argv[6]), argc > 7 ? std::atoi(argv[7]) : 1);
        d.close();
        return rc;
    }
    const bool ok = (mode == "info" && argc == 4) || (mode == "score" && argc == 5) || (mode == "table" && argc >= 7 && argc <= 9);
    if (!ok) {
        std::fprintf(stderr,
                     "usage: xksid-distil info  MODEL QUESTION\n"
                     "       xksid-distil score MODEL QUESTION STATES\n"
                     "       xksid-distil table MODEL QUESTION OUT FIRST LAST [WORKERS [CTX]]\n"
                     "       xksid-distil label MODEL QUESTION IN OUT WIDTH [WORKERS]\n");
        return 2;
    }
    distiller d;
    const int32_t workers = argc > 7 ? std::atoi(argv[7]) : 1;
    if (argc > 8) {
        d.n_ctx = std::atoi(argv[8]);
        if (d.n_ctx < 128 || d.n_ctx > 4096) {
            fail("CTX must be 128 to 4096");
        }
    }
    d.load(argv[2], argv[3]);
    int rc = 0;
    if (mode == "info") {
        rc = mode_info(d);
    } else if (mode == "score") {
        rc = mode_score(d, argv[4]);
    } else {
        rc = mode_table(d, argv[4], std::atoi(argv[5]), std::atoi(argv[6]), workers);
    }
    d.close();
    return rc;
}
