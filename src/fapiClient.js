"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.FAPIClient = void 0;
const axios_1 = __importDefault(require("axios"));
const https = __importStar(require("https"));
const fs = __importStar(require("fs"));
class FAPIClient {
    constructor(config) {
        this.clientId = config.clientId;
        this.clientSecret = config.clientSecret;
        this.tokenEndpoint = config.tokenEndpoint;
        this.requestedScopes = [];
        // Set up mTLS if certificates are provided
        if (config.certPath && config.keyPath) {
            this.httpsAgent = new https.Agent({
                cert: fs.readFileSync(config.certPath),
                key: fs.readFileSync(config.keyPath),
                ca: config.caCertPath ? fs.readFileSync(config.caCertPath) : undefined,
                // Required for self-signed certificates in test environment
                rejectUnauthorized: false
            });
        }
    }
    setRequestedScopes(scopes) {
        this.requestedScopes = scopes;
    }
    getClientCredentialsToken() {
        return __awaiter(this, void 0, void 0, function* () {
            const params = new URLSearchParams();
            params.append('grant_type', 'client_credentials');
            params.append('client_id', this.clientId);
            const authHeader = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');
            const config = {
                method: 'post',
                url: this.tokenEndpoint,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': `Basic ${authHeader}`
                },
                data: params,
                httpsAgent: this.httpsAgent
            };
            try {
                const response = yield (0, axios_1.default)(config);
                return this.handleTokenResponse(response.data);
            }
            catch (error) {
                throw error;
            }
        });
    }
    handleTokenResponse(tokenResponse) {
        // If scopes are not returned, use the requested scopes
        if (!tokenResponse.scope) {
            tokenResponse.scope = this.requestedScopes.join(' ');
        }
        // expires_in is optional according to OAuth 2.0 spec
        // if not present, the client should handle it gracefully
        return tokenResponse;
    }
    getEffectiveScopes(tokenSet) {
        // Return the scopes from the token response if present, otherwise return requested scopes
        return tokenSet.scope ? tokenSet.scope.split(' ') : this.requestedScopes;
    }
}
exports.FAPIClient = FAPIClient;
