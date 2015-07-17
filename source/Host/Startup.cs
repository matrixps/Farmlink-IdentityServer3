/*
 * Copyright 2014 Dominick Baier, Brock Allen
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

using Microsoft.Owin;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Twitter;
using Microsoft.Owin.Security.WsFederation;
using Owin;
using Thinktecture.IdentityServer.Core.Configuration;
using Thinktecture.IdentityServer.Core.Logging;
using Thinktecture.IdentityServer.Core.Services;
using Thinktecture.IdentityServer.Host;
using Thinktecture.IdentityServer.Host.Config;

[assembly: OwinStartup("LocalTest", typeof(Startup_LocalTest))]

namespace Thinktecture.IdentityServer.Host
{
    public class Startup_LocalTest
    {
        public void Configuration(IAppBuilder app)
        {
            LogProvider.SetCurrentLogProvider(new DiagnosticsTraceLogProvider());
            //LogProvider.SetCurrentLogProvider(new TraceSourceLogProvider());

            // uncomment to enable HSTS headers for the host
            // see: https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security
            //app.UseHsts();

            app.Map("/core", coreApp =>
                {
                    var factory = InMemoryFactory.Create(
                        users:   Users.Get(),
                        clients: Clients.Get(),
                        scopes:  Scopes.Get());

                    factory.CustomGrantValidator = 
                        new Registration<ICustomGrantValidator>(typeof(CustomGrantValidator));

                    factory.ConfigureClientStoreCache();
                    factory.ConfigureScopeStoreCache();
                    factory.ConfigureUserServiceCache();

                    var idsrvOptions = new IdentityServerOptions
                    {
                        // TODO: Take this out once certificates are setup --TRH
                        RequireSsl = false,
                        
                        SiteName = "Farmlink Security Services",
                        Factory = factory,
                        SigningCertificate = Cert.Load(),
                        CorsPolicy = CorsPolicy.AllowAll,

                        AuthenticationOptions = new AuthenticationOptions 
                        {
                            //IdentityProviders = ConfigureIdentityProviders,
                            
                        },

                        LoggingOptions = new LoggingOptions
                        {
                            //EnableHttpLogging = true, 
                            //EnableWebApiDiagnostics = true,
                            //IncludeSensitiveDataInLogs = true
                        },

                        EventsOptions = new EventsOptions
                        {
                            RaiseFailureEvents = true,
                            RaiseInformationEvents = true,
                            RaiseSuccessEvents = true,
                            RaiseErrorEvents = true
                        }
                    };

                    coreApp.UseIdentityServer(idsrvOptions);
                });
        }

        public static void ConfigureIdentityProviders(IAppBuilder app, string signInAsType)
        {
           
        }
    }
}