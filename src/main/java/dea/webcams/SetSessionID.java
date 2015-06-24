package dea.webcams;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.CookieStore;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.prefs.BackingStoreException;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SetSessionID {
	public static final String URL_ENCODING = "utf-8";
	public static final String WWW_AUTHENTICATE = "WWW-Authenticate";
	public static final String AUTH_BASIC = "basic";
	public static final String AUTH_DIGEST = "digest";
	public static final String PREF_KEY = "SOFTWARE\\Perspective Software\\Blue Iris\\Cameras";
	public static final String GV_NEW_KEY_MARKER = "<input type=\"hidden\" id=\"IDKey\" name=\"IDKey\" value=\"";
	private static final String loginNameParam = "id";
	private static final String loginPasswordParam = "pwd";
	private static final String loginParam = "ImageType=3";
	private static final String sessionKeyParam = "IDKey";

	protected final Logger log = LoggerFactory.getLogger(getClass());

	protected int retries = 2;
	private String ip;
	protected URL httpsURL;
	protected URL loginURL;
	private String login;
	private String password;
	protected int respCode = 0;
	protected String contentType = "text/text;";

	private Header[] respHeaders;

	protected CloseableHttpClient httpclient;
	// Create a local instance of cookie store
	protected CookieStore cookieStore;

	protected SimpleDateFormat headerDateFormatFull = new SimpleDateFormat(
			"EEE, dd MMM yyyy HH:mm:ss zzz");
	protected SimpleDateFormat headerDateFormat = new SimpleDateFormat(
			"dd MMM yyyy HH:mm:ss zzz");

	protected String userAgentString = "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))";
	protected HttpContext context = new BasicHttpContext();
	protected String sessionId;
	protected String urlMethod = HttpPost.METHOD_NAME;

	public SetSessionID(String ip, String login, String password) {
		this.ip = ip;
		this.login = login;
		this.password = password;
		try {
			loginURL = new URL("http://" + ip + "/phoneinfo");
			// assuming we want max quality available on 600 series for now
			httpsURL = new URL(
					"http://"
							+ ip
							+ "/3G_INFO?ImageType=3&ViewType=1&camera=1&video_size=1&video_quality=1&audio_codec=0");

			// make sure cookies is turn on
			CookieManager ckman = new CookieManager();
			ckman.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
			CookieHandler.setDefault(ckman);
			cookieStore = ckman.getCookieStore();
		} catch (MalformedURLException e) {
			log.error("Copuld not create URLs from IP passed", e);
		}
	}

	protected void shutdownClient() {
		if (httpclient != null) {
			try {
				httpclient.close();
			} catch (IOException e) {
				log.error("Client close failed:", e);
			}
		}
	}

	/**
	 * Executes a request using the default context.
	 * 
	 * @param request
	 *            - the request to execute
	 * @param context
	 *            TODO ignored currently
	 * @return - the response to this request
	 * @throws ClientProtocolException
	 * @throws IOException
	 * @throws ParseException
	 */
	protected HttpResponse execute(HttpUriRequest request, HttpContext context)
			throws ClientProtocolException, IOException, ParseException {
		HttpResponse response = null;
		httpclient = HttpClients.custom().setUserAgent(userAgentString).build();
		// .setDefaultCookieStore(cookieStore)

		log.info("Doing " + request.getMethod() + " to " + request.getURI());
		checkHeaders(request);
		response = httpclient.execute(request); // , context);
		checkHeaders(response, request.getURI());
		respCode = response.getStatusLine().getStatusCode();
		return response;
	}

	/**
	 * Get Last-Modified and Content-Length from headers. Prints headers at info
	 * log level
	 */
	protected void checkHeaders(HttpUriRequest request) throws ParseException {
		log.info("HttpUriRequest:");
		respHeaders = request.getAllHeaders();
		for (Header header : respHeaders) {
			log.info(header.getName() + ":" + header.getValue());
		}
		log.info(getCookies(request.getURI()));
	}

	public String getCookies(URI uri) {
		List<HttpCookie> cookies = cookieStore.get(uri);
		StringBuilder sb = new StringBuilder();
		for (HttpCookie cookie : cookies) {
			sb.append(cookie.getName()).append('=').append(cookie.getValue())
					.append("; ");
		}
		return sb.toString();
	}

	public void setCookies(HttpResponse response, URI uri) {
		for (Header h : response.getHeaders("Set-Cookie")) {
			HttpCookie cookie = new HttpCookie(h.getName(), h.getValue());
			cookieStore.add(uri, cookie);
			log.info("Setting Cookie:" + cookie);
		}
	}

	/**
	 * Get Last-Modified and Content-Length from headers. Prints headers at info
	 * log level
	 */
	protected void checkHeaders(HttpResponse response, URI uri)
			throws ParseException {
		log.info("HttpResponse:");
		if (response != null) {
			respHeaders = response.getAllHeaders();
			for (Header header : respHeaders) {
				log.info(header.getName() + ":" + header.getValue());
				if (header.getName().equals("Content-Type")) {
					contentType = header.getValue();
				} else if (header.getName().equals(sessionKeyParam)) {
					sessionId = header.getValue();
				}
			}
		}
		setCookies(response, uri);
		log.info(getCookies(uri));
	}

	/**
	 * Post login and save session ID if given in response
	 * 
	 * @return HttpResponse
	 */
	protected String login() {
		HttpResponse response = null;
		String responseStr = null;
		try {
			HttpPost request = new HttpPost(new URI(loginURL.toString()));
			List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
			if (loginParam != null) {
				BasicNameValuePair vp = new BasicNameValuePair(loginNameParam,
						login);
				nameValuePairs.add(vp);
				log.info("adding login parm:" + vp);
			}
			if (loginPasswordParam != null) {
				BasicNameValuePair vp = new BasicNameValuePair(
						loginPasswordParam, password);
				nameValuePairs.add(vp);
				log.info("adding login parm:" + vp);
			}
			if (loginParam != null) {
				StringTokenizer parms = new StringTokenizer(loginParam, "&");
				while (parms.hasMoreTokens()) {
					String pair = parms.nextToken();
					int idx = pair.indexOf('=');
					BasicNameValuePair vp = new BasicNameValuePair(
							pair.substring(0, idx), pair.substring(idx + 1));
					nameValuePairs.add(vp);
					log.info("adding login parm:" + vp);
				}
			}
			request.setEntity(new UrlEncodedFormEntity(nameValuePairs));
			response = execute((HttpUriRequest) request, context);
			if (respCode == HttpStatus.SC_OK) {
				HttpEntity entity = response.getEntity();
				if (entity != null) {
					if (contentType.contains("text")) {
						responseStr = EntityUtils.toString(entity);
						log.info("responseStr:" + responseStr);
					}
				}
			}
		} catch (URISyntaxException | IOException | ParseException e) {
			log.error("Failed posting URL", e);
		} finally {
			shutdownClient();
		}
		return responseStr;
	}

	protected HttpUriRequest initRequest(String url) throws URISyntaxException,
			UnsupportedEncodingException {
		if (sessionId != null) {
			if (url.contains("?"))
				url += "&";
			else
				url += "?";

			List<BasicNameValuePair> params = new LinkedList<BasicNameValuePair>();
			params.add(new BasicNameValuePair(sessionKeyParam, sessionId));

			String paramString = URLEncodedUtils.format(params, URL_ENCODING);

			url += paramString;
		}
		HttpUriRequest request = null;
		URI uri;
		if (HttpGet.METHOD_NAME.equals(urlMethod)) {
			uri = new URI(url);
			request = new HttpGet(uri);
		} else if (HttpPost.METHOD_NAME.equals(urlMethod)) {
			uri = new URI(url);
			int i = url.indexOf('?');
			if (i == -1)
				request = new HttpPost(uri);
			else
				request = new HttpPost(new URI(url.substring(0, i)));

			List<NameValuePair> postParams = URLEncodedUtils.parse(uri,
					URL_ENCODING);
			if (postParams != null) {
				((HttpPost) request).setEntity(new UrlEncodedFormEntity(
						postParams));
				log.info("Post parameters : " + postParams);
			}
		} else {
			throw new UnsupportedOperationException(urlMethod + " unsupported");
		}
		String urlStr = uri.toString();
		int i = urlStr.indexOf('?');
		String referer;
		if (i == -1) {
			referer = urlStr;
		} else {
			referer = urlStr.substring(0, i);
		}
		request.setHeader("Host", uri.getHost());
		request.setHeader("User-Agent", userAgentString);
		request.setHeader("Accept",
				"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		request.setHeader("Accept-Language", "en-US,en;q=0.5");
		request.setHeader("Cookie", getCookies(uri));
		request.setHeader("Connection", "keep-alive");
		request.setHeader("Referer", referer);
		request.setHeader("Content-Type", "application/x-www-form-urlencoded");

		return request;
	}

	private Header getAuthHeader(HttpResponse response) {
		Header solution = null;
		try {
			// Get the challenge.
			final Header challenge = response.getHeaders(WWW_AUTHENTICATE)[0];
			String cVal = challenge.getValue().toLowerCase();
			if (cVal.contains(AUTH_BASIC)) {
				final BasicScheme md5Auth = new BasicScheme();
				// Solve it.
				md5Auth.processChallenge(challenge);
				solution = md5Auth.authenticate(
						new UsernamePasswordCredentials(login, password),
						new BasicHttpRequest(HttpGet.METHOD_NAME, httpsURL
								.getPath()), context);

			} else if (cVal.contains(AUTH_DIGEST)) {
				// A org.apache.http.impl.auth.DigestScheme instance is
				// what will process the challenge from the web-server
				final DigestScheme md5Auth = new DigestScheme();
				// Solve it.
				md5Auth.processChallenge(challenge);

				// Generate a solution Authentication header using your
				// username and password.
				solution = md5Auth.authenticate(
						new UsernamePasswordCredentials(login, password),
						new BasicHttpRequest(HttpGet.METHOD_NAME, httpsURL
								.getPath()), context);
				log.info("auth header:" + solution.getName() + ":"
						+ solution.getValue());
			} else {
				log.error("Need way to handle auth for:" + challenge.getValue());
			}
		} catch (MalformedChallengeException | AuthenticationException e) {
			log.error("Failed creating auth header", e);
		}

		return solution;
	}

	protected String executeRequest() {
		String responseStr = null;

		try {
			HttpUriRequest request = initRequest(httpsURL.toString());
			// If we get an HTTP 401 Unauthorized with
			// a challenge to solve.
			HttpResponse response = execute(request, context);
			// Validate that we got an HTTP 401 back
			if (respCode == HttpStatus.SC_UNAUTHORIZED) {
				if (response.containsHeader(WWW_AUTHENTICATE)) {
					shutdownClient();

					// Generate a solution Authentication header using your
					// username and password.
					final Header solution = getAuthHeader(response);
					if (solution != null) {
						log.info("auth header:" + solution.getName() + ":"
								+ solution.getValue());
						// Do another request, but this time include the
						// solution
						// Authentication header as generated by HttpClient.
						request.addHeader(solution);
						try {
							response = execute((HttpUriRequest) request,
									context);
						} catch (Exception e) {
							log.error("Exception connecting to server:", e);
						}
					}
				} else {
					log.error("Service responded with Http 401, "
							+ "but did not send us usable WWW-Authenticate header.");
				}

			}
			if (respCode == HttpStatus.SC_OK) {
				HttpEntity entity = response.getEntity();
				if (entity != null) {
					if (contentType.contains("text")) {
						responseStr = EntityUtils.toString(entity);
						log.info("responseStr:" + responseStr);
					} else {
						responseStr = "content type:" + contentType;
					}
					EntityUtils.consume(entity);
				}
			} else {
				log.error("URL returned:" + respCode);
			}
		} catch (Exception e) {
			log.error("Failed reading URL", e);
			respCode = HttpStatus.SC_GATEWAY_TIMEOUT;
		} finally {
			shutdownClient();
		}

		return responseStr;
	}

	public Header[] getRespHeaders() {
		return respHeaders;
	}

	public void run() throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		log.info("Checking cam:" + ip);
		for (int i = 0; i < retries; i++) {
			String rsp = login();
			if (rsp.contains("IDS_WEB_ID_PWD_ERROR")) {
				log.info(rsp);
				log.error("Login failed");

			} else {
				// check old software type
				int end = rsp.indexOf("</title>");
				if (end > -1) {
					int start = rsp.lastIndexOf(" ", end);
					if (start > -1) {
						sessionId = rsp.substring(start + 1, end);
					}
				}
				if (sessionId == null || sessionId.contains("<title>")) {
					// check new software type
					int start = rsp.indexOf(GV_NEW_KEY_MARKER);
					if (start > -1) {
						start += GV_NEW_KEY_MARKER.length();
						end = rsp.indexOf("\"", start);
						if (start > -1) {
							sessionId = rsp.substring(start, end);
						}
					}

				}
				String s = executeRequest();

				if (respCode == HttpURLConnection.HTTP_OK) {
					log.info(s);
					String rtsp = "rtsp://" + ip + ":8554/";
					int start = s.indexOf(rtsp);
					if (start > -1) {
						start = start + rtsp.length() + 7;
						if (start > -1) {
							end = s.indexOf('"', start);
							RegUtil.replaceID(ip, s.substring(start, end));
						}
					}
					break;
				} else {
					StringBuilder sb = new StringBuilder();
					if (getRespHeaders() != null) {
						sb.append("Response Headers:<br>");
						for (Header header : getRespHeaders()) {
							sb.append(header.getName()).append(":")
									.append(header.getValue()).append("<br>");
						}
					}
					log.info(sb.toString());
				}
			}
		}
		log.warn("read url");
	}

	public static void main(String[] args) throws BackingStoreException {
		try {
			if (args.length < 3 || !args[0].contains(".")) {
				System.err
						.println("USAGE:SetSessionID IP_of_server login password");
			} else {
				SetSessionID s = new SetSessionID(args[0], args[1], args[2]);
				s.run();
				System.out.println("Done");
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Failed to update registry");
			System.exit(1);
		}
	}
}
