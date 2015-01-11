# GvBi
Blue Iris does not directly support monitoring of Geovision servers but you can get it to work by getting a RTSP url via the /phonepwd.htm interface. The problem is these URLs contain config and session info encoded in the URL. When the session is reset you normally have to update each camera separately. After updating to Blue Iris version 4 the problem seemed to get worse so I wrote this to automate the process.
This a just quick and dirty program update Blue Iris rtsp URLs held in the registry. The best way to call it is to go into the watchdog tab for the camera. See BlurIrisGVconfig.rtf for details.
Note the program updates all the URLs pointed at the server passed since getting a new session tends to cause the current session to time out.
