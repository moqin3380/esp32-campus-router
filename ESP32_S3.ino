/*
 * ESP32-S3 校园网共享路由
 * 深澜 SRun 协议自动认证 + NAPT 转发, WiFi 直连
 * 全流程自检日志版
 *
 * 依赖: Arduino ESP32 Core >= 3.0.0  (必须!)
 *   原因: NAPT(网络地址端口转换) 依赖 esp_netif_napt_enable()，
 *         该函数自 core 3.0.0 / IDF 5.x 起才提供。
 *         core 2.0.x 的预编译 liblwip.a 中 IP_FORWARD/IP_NAPT 均未开启
 *         (sdkconfig: "# CONFIG_LWIP_IP_FORWARD is not set")，
 *         ip4_napt.c.obj 为空对象, 任何 NAPT 符号都链接不到。
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include "mbedtls/md5.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ============ 编译期能力探测 ============ */
#include "esp_arduino_version.h"

#if defined(ESP_ARDUINO_VERSION_MAJOR) && (ESP_ARDUINO_VERSION_MAJOR < 3)
  #warning "arduino-esp32 core < 3.0.0 : NAPT 不可用, 共享上网功能将失效, 请升级 core"
  #define ESP32S3_HAVE_NAPT 0
#else
  #define ESP32S3_HAVE_NAPT 1
#endif

/* ============ 用户配置（全部需自行填写） ============
 *
 * 【步骤 1】确定学校 WiFi
 *   用手机/电脑扫描 2.4G WiFi，记下目标 SSID。
 *   注意 ESP32-S3 只支持 2.4GHz，不支持 5GHz。
 *   若该 WiFi 有密码就填密码；若是开放网络（无密码）留空字符串 ""。
 */
#define CAMPUS_SSID   "校园网WiFi名称"        /* ← 学校 2.4G WiFi 名 */
#define CAMPUS_PASS   ""                      /* ← WiFi 密码；开放网络留空 */

/* 【步骤 2】确定 Portal 地址
 *   浏览器访问该地址，看能否弹出校园网登录页。
 *   常见形式: http://<网关地址> 或学校指定页面。
 */
#define PORTAL        "http://校园网IP地址"    /* ← 如 http://192.168.x.x */

/* 【步骤 3】填写认证账号
 *   注意：这里填的是校园网账号密码，不是 WiFi 密码。
 */
#define USERNAME      "学号"                  /* ← 学号 / 账号 */
#define PASSWORD      "校园网密码"             /* ← 校园网密码 */
#define AC_ID         "认证点编号"              /* ← ACID，通常是 "1"，见登录页 URL */

/* 【步骤 4】设置自建热点（手机连这个上网） */
#define AP_SSID       "你的热点名称"            /* ← 热点名 */
#define AP_PASS       "你的热点密码"            /* ← 热点密码，WPA2 要求至少 8 位 */

#define AP_CHANNEL    1                       /* ← 实际运行会自动跟随 STA 信道，此项仅作初始值 */
#define KEEPALIVE_MS  120000                  /* ← 认证保活间隔(ms)，120 秒 */
/* ================================== */

static unsigned long lastKA = 0;

/* ---------- hex ---------- */
String hx(const uint8_t *d, size_t n){
  String s; char b[3];
  for(size_t i=0;i<n;i++){sprintf(b,"%02x",d[i]);s+=b;}
  return s;
}
String md5s(const String &in){
  unsigned char d[16];
  mbedtls_md5((const unsigned char*)in.c_str(), in.length(), d);
  return hx(d,16);
}
String hmacMd5s(const String &key,const String &msg){
  unsigned char o[16]; mbedtls_md_context_t c;
  const mbedtls_md_info_t*i=mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
  mbedtls_md_init(&c); mbedtls_md_setup(&c,i,1);
  mbedtls_md_hmac_starts(&c,(const unsigned char*)key.c_str(),key.length());
  mbedtls_md_hmac_update(&c,(const unsigned char*)msg.c_str(),msg.length());
  mbedtls_md_hmac_finish(&c,o); mbedtls_md_free(&c);
  return hx(o,16);
}

/* ---------- base64 (自定义字母表) ---------- */
/* 深澜 SRun 专用字母表, 不是标准 base64! */
static const char SRUN_B64[] = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
String b64srun(const String &in){
  String o; int i=0,n=in.length();
  while(i<n){
    uint32_t v=((uint8_t)in[i++])<<16; bool a=(i<n); if(a)v|=((uint8_t)in[i++])<<8;
    bool b=(i<n); if(b)v|=((uint8_t)in[i++]);
    o+=SRUN_B64[(v>>18)&63]; o+=SRUN_B64[(v>>12)&63];
    o+=a?SRUN_B64[(v>>6)&63]:'='; o+=b?SRUN_B64[v&63]:'=';
  }
  return o;
}

/* ---------- ★ XXTEA 加密 (深澜 SRBX1 核心) ---------- */
/* 完全对照 Portal.js 的 encode()/s()/l() 逐行翻译 */
static uint32_t* xxtea_s(const String &a, bool b, int &vlen){
  int c = a.length();
  int n = (c + 3) / 4 + (b ? 1 : 0);
  uint32_t *v = new uint32_t[n];
  int vi = 0;
  for(int i=0;i<c;i+=4){
    uint32_t x = (uint8_t)a[i];
    if(i+1<c) x |= (uint32_t)(uint8_t)a[i+1]<<8;
    if(i+2<c) x |= (uint32_t)(uint8_t)a[i+2]<<16;
    if(i+3<c) x |= (uint32_t)(uint8_t)a[i+3]<<24;
    v[vi++] = x;
  }
  if(b) v[vi++] = c;
  vlen = vi;
  return v;
}

String xxteaEncode(const String &str, const String &key){
  if(str.length()==0) return "";

  int vlen, klen;
  uint32_t *v = xxtea_s(str, true, vlen);
  uint32_t *k = xxtea_s(key, false, klen);
  if(klen < 4) klen = 4;   /* JS: if(k.length<4) k.length=4 (pad with 0) */

  int n = vlen - 1;
  if(n < 0){ delete[] v; delete[] k; return ""; }
  uint32_t z = v[n], y = v[0], c = 0x9E3779B9, m, e, p;
  int q = 6 + 52/(n+1);
  uint32_t d = 0;

  while(q-- > 0){
    d = (d + c) & 0xFFFFFFFF;
    e = (d >> 2) & 3;
    for(p=0; p<(uint32_t)n; p++){
      y = v[p+1];
      m = (z>>5) ^ (y<<2);
      m += (y>>3) ^ (z<<4) ^ (d ^ y);
      m += k[(p & 3) ^ e] ^ z;
      z = v[p] = (v[p] + m) & 0xFFFFFFFF;
    }
    y = v[0];
    m = (z>>5) ^ (y<<2);
    m += (y>>3) ^ (z<<4) ^ (d ^ y);
    m += k[(p & 3) ^ e] ^ z;
    z = v[n] = (v[n] + m) & 0xFFFFFFFF;
  }

  /* l(v, false): 每 32 位转 4 字节, 小端 */
  String out;
  out.reserve(vlen*4);
  for(int i=0;i<vlen;i++){
    uint32_t x = v[i];
    out += (char)(x & 0xff);
    out += (char)((x>>8) & 0xff);
    out += (char)((x>>16) & 0xff);
    out += (char)((x>>24) & 0xff);
  }
  delete[] v; delete[] k;
  return out;
}

/* info 加密: {SRBX1} + base64( xxtea(json, token) ) */
String srunInfoEnc(const String &json, const String &token){
  return "{SRBX1}" + b64srun(xxteaEncode(json, token));
}

/* ---------- JSON 取值 ---------- */
String jget(const String &j,const String &k){
  String kk="\""+k+"\""; int p=j.indexOf(kk); if(p<0)return "";
  p=j.indexOf(':',p+kk.length()); if(p<0)return ""; p++;
  while(p<(int)j.length()&&(j[p]==' '||j[p]=='"'))p++;
  int e=p; while(e<(int)j.length()&&j[e]!='"'&&j[e]!=','&&j[e]!='}')e++;
  return j.substring(p,e);
}

/* ---------- URL 编码 (application/x-www-form-urlencoded) ---------- */
String urlEnc(const String &s){
  const char *hex="0123456789ABCDEF";
  String o; o.reserve(s.length()+16);
  for(size_t i=0;i<s.length();i++){
    unsigned char c=(unsigned char)s[i];
    if((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||
       c=='-'||c=='_'||c=='.'||c=='~'||c=='*'){
      o+=(char)c;
    }else{
      o+='%'; o+=hex[c>>4]; o+=hex[c&15];
    }
  }
  return o;
}

/* ---------- HTTP ---------- */
String get(const String &url){
  HTTPClient h; h.begin(url); h.setTimeout(8000);
  h.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
  h.addHeader("Referer", String(PORTAL)+"/index_1.html");
  int c=h.GET(); String r; if(c>0)r=h.getString(); h.end();
  Serial.printf("[GET %d] %s\n-> %.250s\n",c,url.c_str(),r.c_str());
  return r;
}
String post(const String &url,const String &body){
  HTTPClient h; h.begin(url); h.setTimeout(8000);
  h.addHeader("Content-Type","application/x-www-form-urlencoded");
  h.addHeader("Referer", String(PORTAL)+"/index_1.html");
  h.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
  int c=h.POST(body); String r; if(c>0)r=h.getString(); h.end();
  Serial.printf("[POST %d] %s\n-> %.300s\n",c,url.c_str(),r.c_str());
  return r;
}

/* ---------- SHA1 (深澜 chksum 用, 不是 SHA256!) ---------- */
#include "mbedtls/sha1.h"
String sha1s(const String &in){
  unsigned char d[20];
  mbedtls_sha1((const unsigned char*)in.c_str(), in.length(), d);
  return hx(d,20);
}

/* ---------- 登录 ---------- */
/* 算法完全对照 Portal.js (深澜 V2.00.20221130 / SRunCGIAuthIntfSvr V1.18):
 *   hmd5  = HMAC-MD5(key=token, msg=password)
 *   info  = {SRBX1} + b64_custom( xxtea( json, token ) )   json里 password 是明文!
 *   chksum= SHA1( token+user+token+hmd5+token+acid+token+ip
 *                 +token+n+token+type+token+info )
 *   POST password = "{MD5}" + hmd5
 */

bool srunLogin(){
  if(WiFi.status()!=WL_CONNECTED) return false;
  String ip = WiFi.localIP().toString();
  String ts = String(millis());

  Serial.println("\n--------- LOGIN START ---------");
  Serial.printf("[IP ] %s\n", ip.c_str());

  /* 0) 先查是否在线 */
  String ru = get(String(PORTAL)+"/cgi-bin/rad_user_info?callback=x&_="+ts);
  String oip = jget(ru,"online_ip");
  if(oip.length()>0 && ru.indexOf("not_online")<0){
    Serial.printf("[+] already online, portal_ip=%s\n", oip.c_str());
    return true;
  }
  String useip = (oip.length()>0)? oip : ip;
  Serial.printf("[USE] login_ip=%s\n", useip.c_str());

  /* 1) challenge (token) */
  String cr = get(String(PORTAL)+"/cgi-bin/get_challenge?callback=x&username="
                  +USERNAME+"&ip="+useip+"&_="+ts);
  String token = jget(cr,"challenge");
  if(token.length()==0){ Serial.println("[X] no challenge"); return false; }
  Serial.printf("[TOKEN] %s\n", token.c_str());

  /* 2) hmd5 = HMAC-MD5(key=token, msg=password) */
  String hmd5 = hmacMd5s(token, PASSWORD);
  Serial.printf("[HMD5] %s\n", hmd5.c_str());

  /* 3) info: json 里 password 是明文! enc_ver=srun_bx1 */
  String json = "{\"username\":\""+String(USERNAME)+
                "\",\"password\":\""+PASSWORD+
                "\",\"ip\":\""+useip+
                "\",\"acid\":\""+String(AC_ID)+
                "\",\"enc_ver\":\"srun_bx1\"}";
  String info = srunInfoEnc(json, token);
  Serial.printf("[INFO] %s\n", info.c_str());

  /* 4) chksum = SHA1(拼接) */
  String str = token+USERNAME+
               token+hmd5+
               token+AC_ID+
               token+useip+
               token+"200"+
               token+"1"+
               token+info;
  String chk = sha1s(str);
  Serial.printf("[CHK ] %s\n", chk.c_str());

  /* 5) POST — info 含 +/=/ 字符, 必须 URL 编码, 否则服务器解析出错 → sign_error */
  String body="action=login&username="+String(USERNAME)+
              "&password={MD5}"+hmd5+
              "&ac_id="+String(AC_ID)+"&ip="+useip+
              "&chksum="+chk+"&info="+urlEnc(info)+
              "&n=200&type=1&os=Windows+10&name=Windows&double_stack=0";
  Serial.printf("[BODY] len=%d\n", body.length());
  String lr = post(String(PORTAL)+"/cgi-bin/srun_portal?callback=x&_="+ts, body);

  /* 详细判读响应 */
  Serial.printf("[RESP] len=%d raw=[%s]\n", lr.length(), lr.c_str());
  if(lr.indexOf("login_ok")>=0||lr.indexOf("\"error\":\"ok\"")>=0||
     lr.indexOf("\"res\":\"ok\"")>=0||lr.indexOf("suc_msg")>=0){
    Serial.println("============== LOGIN OK ==============");
    return true;
  }
  if(lr.indexOf("sign_error")>=0)  Serial.println("[X] sign_error = chksum 不匹配");
  if(lr.indexOf("password_error")>=0) Serial.println("[X] password_error = 账号密码错");
  String em = jget(lr,"error_msg");
  if(em.length()>0) Serial.printf("[ERR] error_msg=%s\n", em.c_str());
  String ev = jget(lr,"error");
  if(ev.length()>0) Serial.printf("[ERR] error=%s\n", ev.c_str());
  Serial.println("[X] LOGIN FAILED");
  return false;
}

/* ---------- NAPT ---------- */
/* 运行期确认: AP netif 已 up 且已拿到 192.168.4.1 之类的地址 */
static bool apReady(){
  esp_netif_t *ap = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if(!ap) return false;
  esp_netif_ip_info_t ip;
  if(esp_netif_get_ip_info(ap,&ip)!=ESP_OK) return false;
  return ip.ip.addr != 0;
}

void napt(){
  esp_netif_t *ap = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if(!ap){ Serial.println("[NAPT] no ap netif"); return; }

#if ESP32S3_HAVE_NAPT
  /* core >= 3.0.0 : 官方 API, 原型在 esp_netif.h */
  esp_err_t err = esp_netif_napt_enable(ap);
  if(err==ESP_OK){
    Serial.printf("[NAPT] OK  ap=%s\n",
      WiFi.softAPIP().toString().c_str());
  }else{
    Serial.printf("[NAPT] FAIL err=0x%X (%s)  检查 CONFIG_LWIP_IPV4_NAPT\n",
      (unsigned)err, esp_err_to_name(err));
  }
#else
  Serial.println("[NAPT] SKIP: core < 3.0.0, 本 SDK 未编译 IP_FORWARD/IP_NAPT");
  Serial.println("       -> 工具 -> 开发板管理器 升级 esp32 到 3.x");
#endif
}

/* AP netif 起来后延迟再开 NAPT: AP_START 事件触发时 netif 尚未 fully up */
static void naptTask(void *){
  for(int i=0;i<20;i++){          /* 最多等 10s */
    vTaskDelay(pdMS_TO_TICKS(500));
    if(apReady()){ napt(); vTaskDelete(NULL); return; }
  }
  Serial.println("[NAPT] timeout waiting ap netif");
  vTaskDelete(NULL);
}

/* ---------- STA 重连节流 ---------- */
static unsigned long lastTry = 0;
static uint32_t      retryCnt = 0;
#define RETRY_MIN_MS 5000            /* 最短重试间隔, 防止死循环刷屏 */

/* 把 WiFi 断开原因翻译成人话 */
static const char* discReason(uint8_t r){
  switch(r){
    case WIFI_REASON_NO_AP_FOUND:          return "找不到该SSID (名字错/超出范围/是5G频段)";
    case WIFI_REASON_AUTH_FAIL:            return "认证失败 (密码错/需要802.1x企业认证)";
    case WIFI_REASON_ASSOC_FAIL:           return "关联失败 (AP拒绝/信号太弱)";
    case WIFI_REASON_HANDSHAKE_TIMEOUT:    return "握手超时 (密码错或信号差)";
    case WIFI_REASON_CONNECTION_FAIL:      return "连接失败";
    case WIFI_REASON_BEACON_TIMEOUT:       return "信标丢失 (AP关机/太远)";
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:return "四次握手超时 (密码错)";
    case WIFI_REASON_AUTH_EXPIRE:          return "认证过期";
    case WIFI_REASON_802_1X_AUTH_FAILED:   return "802.1x 企业认证失败";
    default:                               return "未知原因";
  }
}

/* 扫描一次, 确认目标 SSID 到底在不在 2.4G 列表里 */
static void scanCheck(){
  Serial.println("[SCAN] 开始扫描 2.4G AP ...");
  int n = WiFi.scanNetworks();
  if(n <= 0){ Serial.println("[SCAN] 一个都没扫到! 天线/供电/射频问题"); return; }

  bool found = false;
  for(int i=0;i<n;i++){
    String s = WiFi.SSID(i);
    Serial.printf("  %2d) ch=%-3ld rssi=%-4ld %s%s\n",
      i+1, (long)WiFi.channel(i), (long)WiFi.RSSI(i),
      s.c_str(),
      (s==String(CAMPUS_SSID)) ? "   <<< 目标!" : "");
    if(s==String(CAMPUS_SSID)) found = true;
  }
  if(found) Serial.println("[SCAN] 目标 SSID 在线, 问题在密码/认证方式");
  else      Serial.println("[SCAN] 目标 SSID 不在列表! 检查名字拼写或改用2.4G");
  WiFi.scanDelete();
}

/* 统一连接入口: 开放网络(空密码)要用单参版本, 否则可能关联失败 */
static void staConnect(){
  if(String(CAMPUS_PASS).length() == 0){
    WiFi.begin(CAMPUS_SSID);                      /* 开放/无密码 */
  }else{
    WiFi.begin(CAMPUS_SSID, CAMPUS_PASS);
  }
}

/* 统一的重连入口: 带节流 */
static void tryReconnect(const char *why){
  if(millis()-lastTry < RETRY_MIN_MS) return;   /* 节流: 5s 内只发一次 */
  lastTry = millis();
  retryCnt++;
  Serial.printf("[STA] retry #%lu (%s)\n", (unsigned long)retryCnt, why);
  /* 不在这里扫描: scanNetworks 会占满射频 2~3 秒, 严重拖垮吞吐。
     诊断用的扫描只在开机 setup() 里做一次。 */
  staConnect();
}

/* ---------- 事件 ---------- */
/* 用双参回调 WiFiEventFuncCb, 才能拿到断开原因 reason */
void onEvt(arduino_event_id_t e, arduino_event_info_t info){
  if(e==ARDUINO_EVENT_WIFI_STA_GOT_IP){
    Serial.printf("[STA] IP=%s  RSSI=%d\n",
      WiFi.localIP().toString().c_str(), WiFi.RSSI());
    retryCnt = 0;
    lastKA=millis();

    /* ★ AP 必须与 STA 同信道共存, 所以等 STA 连上拿到信道后再起热点 */
    {
      static bool apStarted = false;
      if(!apStarted){
        apStarted = true;
        int ch = WiFi.channel();
        Serial.printf("[AP ] starting on ch%d ...\n", ch);
        WiFi.softAP(AP_SSID, AP_PASS, ch);
        Serial.printf("[AP ] %s  ip=%s\n",
          WiFi.softAPIP() != IPAddress(0,0,0,0) ? "up" : "FAIL",
          WiFi.softAPIP().toString().c_str());
        /* AP 已起, 直接开 NAPT (不依赖 AP_START 事件) */
        xTaskCreate(naptTask,"napt",4096,NULL,1,NULL);
      }
    }

    srunLogin();
  }
  else if(e==ARDUINO_EVENT_WIFI_STA_DISCONNECTED){
    static unsigned long lastLog = 0;
    if(millis()-lastLog > 3000){          /* 日志也节流, 不刷屏 */
      lastLog = millis();
      uint8_t r = info.wifi_sta_disconnected.reason;
      Serial.printf("[STA] disconnect reason=%u : %s\n", r, discReason(r));
    }
    tryReconnect("disconnected");
  }
  else if(e==ARDUINO_EVENT_WIFI_AP_START){
    Serial.println("[AP ] up");
    xTaskCreate(naptTask,"napt",4096,NULL,1,NULL);
  }
}

void setup(){
  Serial.begin(115200); delay(1200);
  Serial.println("\n=== ESP32-S3-N16R8 Campus Router ===");
  Serial.printf("core  %d.%d.%d\n",
    ESP_ARDUINO_VERSION_MAJOR,ESP_ARDUINO_VERSION_MINOR,ESP_ARDUINO_VERSION_PATCH);
  Serial.printf("PSRAM %u KB\n",(unsigned)(ESP.getFreePsram()/1024));

  /* ★ 事件回调最先注册 */
  WiFi.onEvent(onEvt);

  WiFi.mode(WIFI_AP_STA);

  /* ★ 只配置网段, 不在这里 softAP —— 等 STA 连上后按实际信道起 AP */
  IPAddress apip(192,168,4,1), apmask(255,255,255,0);
  WiFi.softAPConfig(apip,apip,apmask);

  /* 注意: 不要手动下发 AP 的 DNS。
   * ESP32 softAP 默认由框架自己做 DNS 转发(客户端 53 端口 -> 上游),
   * 强行指定外部 DNS 会让客户端绕过转发直连公网, 查询超时导致下载极慢。
   * 曾下发 114.114.114.114 导致下行从 8M 掉到 <1M, 已回退。 */

  /* 开机先扫一次, 确认目标 SSID 是否可见 —— 排查第一现场 */
  scanCheck();

  staConnect();
  Serial.printf("connecting %s ...\n",CAMPUS_SSID);
}
void loop(){
  /* keepalive: 断线重连, 在线则刷新认证 */
  if(millis()-lastKA>=KEEPALIVE_MS){
    lastKA=millis();
    if(WiFi.status()==WL_CONNECTED){
      Serial.println("[KA ] re-auth");
      srunLogin();
    }else{
      Serial.println("[KA ] sta down, reconnect");
      staConnect();
    }
  }
  delay(200);
}