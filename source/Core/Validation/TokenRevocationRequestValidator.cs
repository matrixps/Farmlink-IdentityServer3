/*
 * Copyright 2014, 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using System;
using System.Collections.Specialized;
using System.Threading.Tasks;

namespace IdentityServer3.Core.Validation
{
    internal class TokenRevocationRequestValidator
    {
        private readonly ITokenHandleStore _tokenHandles;
        private readonly IRefreshTokenStore _refreshTokens;

        public TokenRevocationRequestValidator(ITokenHandleStore tokenHandles, IRefreshTokenStore refreshTokens)
        {
            _tokenHandles = tokenHandles;
            _refreshTokens = refreshTokens;
        }

        public Task<TokenRevocationRequestValidationResult> ValidateRequestAsync(NameValueCollection parameters, Client client)
        {
            if (parameters == null) throw new ArgumentNullException("parameters");
            if (client == null) throw new ArgumentNullException("client");

            var success = new TokenRevocationRequestValidationResult { IsError = false };
            var fail = new TokenRevocationRequestValidationResult { IsError = true };
            
            ////////////////////////////
            // either token OR sub must be present
            ///////////////////////////
            var token = parameters.Get("token");
            var sub = parameters.Get("sub");

            // both are missing
            if (token.IsMissing() && sub.IsMissing())
            {
                fail.Error = Constants.TokenErrors.InvalidRequest;
                return Task.FromResult(fail);
            }

            // both are present
            if (token.IsPresent() && sub.IsPresent())
            {
                fail.Error = Constants.TokenErrors.InvalidRequest;
                return Task.FromResult(fail);
            }

            if (sub.IsPresent())
            {
                success.Mode = TokenRevocationMode.Subject;
                success.SubjectId = sub;

                return Task.FromResult(success);
            }

            if (token.IsPresent())
            {
                success.Mode = TokenRevocationMode.Token;
                success.Token = token;
            }
           
            ////////////////////////////
            // check token type hint
            ///////////////////////////
            var hint = parameters.Get("token_type_hint");
            if (hint.IsPresent())
            {
                if (Constants.SupportedTokenTypeHints.Contains(hint))
                {
                    success.TokenTypeHint = hint;
                }
                else
                {
                    fail.Error = Constants.RevocationErrors.UnsupportedTokenType;
                    return Task.FromResult(fail);
                }
            }

            return Task.FromResult(success);
        }
    }
}