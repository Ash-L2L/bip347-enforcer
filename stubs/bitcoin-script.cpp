#include <vector>

#include <policy/policy.h>
#include <primitives/transaction.h>
#include <node/protocol_version.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <streams.h>

extern "C" {
    unsigned int mandatory_script_verify_flags() {
        return MANDATORY_SCRIPT_VERIFY_FLAGS;
    }

    unsigned int standard_script_verify_flags() {
        return STANDARD_SCRIPT_VERIFY_FLAGS;
    }

    unsigned int op_cat_verify_flag() {
        return SCRIPT_VERIFY_OP_CAT;
    }

    struct VerifyScriptResult {
        bool success;
        char* err_msg;

        VerifyScriptResult(bool success, const std::string& err_msg)
        : success(success), err_msg(nullptr) {
            if (!err_msg.empty()) {
                this->err_msg = strdup(err_msg.c_str());  // Duplicate the string
            }
        }

        // Destructor to free the allocated memory
        ~VerifyScriptResult() {
            if (this->err_msg != nullptr) {
                free(this->err_msg);
            }
        }
    };

    VerifyScriptResult* verify_script(const uint8_t* scriptPubKey, uint32_t scriptPubKeyLen,
                       const uint8_t* txTo, uint32_t txToLen,
                       unsigned int nIn, unsigned int flags,
                       int64_t amount_in) {
        // Convert inputs to appropriate types
        std::vector<uint8_t> vscriptPubKey(scriptPubKey, scriptPubKey + scriptPubKeyLen);
        std::vector<uint8_t> vtxTo(txTo, txTo + txToLen);

        // Parse the transaction
        DataStream stream(vtxTo);
        const CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

        // Verify the script
        ScriptError scriptErr;
        bool success = VerifyScript(
            tx.vin[nIn].scriptSig, CScript(vscriptPubKey.begin(), vscriptPubKey.end()), 
            &tx.vin[nIn].scriptWitness, flags, 
            TransactionSignatureChecker(&tx, nIn, amount_in, MissingDataBehavior::FAIL),
            &scriptErr
        );
        if (success) {
            return new VerifyScriptResult(success, "");
        } else {
            std::string err_msg = ScriptErrorString(scriptErr);
            return new VerifyScriptResult(success, err_msg);
        }
    }

    /// MUST call when dropping VerifyScriptResult
    void free_verify_script_result(VerifyScriptResult* result) {
        delete result;
    }
}
