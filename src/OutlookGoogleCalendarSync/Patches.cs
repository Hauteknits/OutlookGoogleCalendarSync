using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Requests;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Util.Store;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Google.Apis.Logging;
using System.Net;
using System.Diagnostics;
using System.Collections.Specialized;
using System.IO;
using log4net;

namespace OutlookGoogleCalendarSync.Google {
    public class CustomGoogleWebAuthenticationBroker : GoogleWebAuthorizationBroker {
        public static async Task<UserCredential> AuthorizeAsync(GoogleAuthorizationCodeFlow.Initializer initializer, IEnumerable<string> scopes, string user, bool usePkce, CancellationToken taskCancellationToken, IDataStore dataStore = null, ICodeReceiver codeReceiver = null) {
            initializer.Scopes = scopes;
            initializer.DataStore = dataStore ?? new FileDataStore(Folder);
            GoogleAuthorizationCodeFlow flow = (usePkce ? new PkceGoogleAuthorizationCodeFlow(initializer) : new GoogleAuthorizationCodeFlow(initializer));
            codeReceiver = codeReceiver ?? new LocalServerCodeReceiver();
            return await new CustomAuthorizationCodeInstalledApp(flow, codeReceiver).AuthorizeAsync(user, taskCancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
    }

    public class CustomAuthorizationCodeInstalledApp : AuthorizationCodeInstalledApp {
        private readonly IPkceAuthorizationCodeFlow flow;

        private readonly ICodeReceiver codeReceiver;

        public IAuthorizationCodeFlow Flow => flow;

        public ICodeReceiver CodeReceiver => codeReceiver;
        public CustomAuthorizationCodeInstalledApp(IAuthorizationCodeFlow flow, ICodeReceiver codeReceiver) : base(flow, codeReceiver) {
        }

        public async Task<UserCredential> AuthorizeAsync(string userId, CancellationToken taskCancellationToken) {
            TokenResponse bytes = await Flow.LoadTokenAsync(userId, taskCancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            if (ShouldRequestAuthorizationCode(bytes)) {
                string redirectUri = CodeReceiver.RedirectUri;
                string codeVerifier;
                AuthorizationCodeRequestUrl url = this.flow.CreateAuthorizationCodeRequest(redirectUri, out codeVerifier);
                AuthorizationCodeResponseUrl authorizationCodeResponseUrl = await CodeReceiver.ReceiveCodeAsync(url, taskCancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                if (string.IsNullOrEmpty(authorizationCodeResponseUrl.Code)) {
                    TokenErrorResponse tokenErrorResponse = new TokenErrorResponse(authorizationCodeResponseUrl);
                    throw new TokenResponseException(tokenErrorResponse);
                }
                bytes = await this.flow.ExchangeCodeForTokenAsync(userId, authorizationCodeResponseUrl.Code, codeVerifier, redirectUri, taskCancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
            return new UserCredential(this.flow, userId, bytes);
        }
    }

    public class CustomCodeReciever : LocalServerCodeReceiver {
        private static readonly ILog log = LogManager.GetLogger(typeof(Authenticator));

        protected override bool OpenBrowser(string url) {
            log.Debug("URL: " + url);
            Process.Start(new ProcessStartInfo {
                FileName = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                Arguments = url,
                UseShellExecute = false
            });
            return true;
        }
    }

}
