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
const axios_1 = __importDefault(require("axios"));
const fapiClient_1 = require("../fapiClient");
const path = __importStar(require("path"));
jest.mock('axios');
describe('FAPI Token Endpoint Tests', () => {
    const config = {
        clientId: '2d4c95a7-6dc3-4416-ab1c-ea44501635aa',
        clientSecret: 'ae149792-aeb9-40c6-9498-5f64d65262b1',
        tokenEndpoint: 'https://localhost.emobix.co.uk:8444/test-mtls/a/ais-corporate/token',
        certPath: path.join(__dirname, '../certs/client.crt'),
        keyPath: path.join(__dirname, '../certs/client.key'),
        caCertPath: path.join(__dirname, '../certs/ca.crt')
    };
    const requestedScopes = ['openid', 'payments'];
    let fapiClient;
    beforeEach(() => {
        fapiClient = new fapiClient_1.FAPIClient(config);
        fapiClient.setRequestedScopes(requestedScopes);
        jest.clearAllMocks();
    });
    test('should handle token response without scopes and expires_in', () => __awaiter(void 0, void 0, void 0, function* () {
        // Mock the token response without scopes and expires_in
        const mockTokenResponse = {
            data: {
                access_token: 'mock_access_token',
                token_type: 'Bearer'
                // Note: No scope or expires_in fields
            }
        };
        axios_1.default.mockResolvedValueOnce(mockTokenResponse);
        // Act
        const response = yield fapiClient.getClientCredentialsToken();
        // Assert
        expect(response.access_token).toBeDefined();
        expect(response.token_type).toBe('Bearer');
        expect(response.expires_in).toBeUndefined();
        expect(response.scope).toBe(requestedScopes.join(' '));
        // Verify the request was made with correct parameters
        expect(axios_1.default).toHaveBeenCalledWith(expect.objectContaining({
            method: 'post',
            url: config.tokenEndpoint,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': expect.stringContaining('Basic ')
            },
            data: expect.any(URLSearchParams),
            httpsAgent: expect.any(Object)
        }));
        // Verify the effective scopes
        const effectiveScopes = fapiClient.getEffectiveScopes(response);
        expect(effectiveScopes).toEqual(requestedScopes);
    }));
});
