#ifndef _TPLINK_H
#define _TPLINK_H

// origin auth js code
/*
this.orgAuthPwd = function(a){return this.securityEncode(a, "RDpbLfCPsJZ7fiv", "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW")};
this.securityEncode = function(a, c, b)
{
    var d = "", e, f, g, h, k = 187, m = 187;
    f = a.length;
    g = c.length;
    h = b.length;
    e = f > g ? f : g;
    for (var l = 0; l < e; l++)
        m = k = 187, l >= f ? m = c.charCodeAt(l) : l >= g ? k = a.charCodeAt(l) : (k = a.charCodeAt(l), m = c.charCodeAt(l)), d += b.charAt((k ^ m) % h);
    return d
};
*/

/* *** there is not finish yet *** */
char *TPLINK_POST_REQUEST = "POST /goform/formLogin HTTPMethod/1.1\r\n"
                            "Host: %s\r\n"
                            "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n"
                            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                            "Accept-Language: en-US,en;q=0.5\r\n"
                            "Accept-Encoding: gzip, deflate\r\n"
                            "Referer: %s\r\n"
                            "Content-Type: application/x-www-form-urlencoded\r\n"
                            "Content-Length: %ld\r\n"
                            "Connection: close\r\n"
                            "Upgrade-Insecure-Requests: 1\r\n\r\n"
                            "%s";
char *TPLINK_POST_REQUEST_DATA = "Language=Chinese&Language_set=Chinese&username=%s&password=%s&submit=%%E7%%99%%BB%%E5%%BD%%95";
char *TPLINK_SUCCESS = "quick_setup1.asp";

#endif