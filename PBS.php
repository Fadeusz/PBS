<?php

class PBS {
	private $cookie = array();
    private $referer = '';
    private $referer_ = '';

    public $error = 0;

    public $info;

    public $result;

    public function __construct ()
    {

    }

    public function __destruct ()
    {

    }

    function search_cookie($result)
    {
        preg_match_all('/Set-Cookie: (.*?)=(.*?)($|;|,(?! ))/is',$result,$arr);
        
        if( count( $arr[1] ) )
        {
            foreach($arr[1] as $b => $a)
            {
                $this->cookie[$arr[1][$b]] = $arr[2][$b];
            }
        }
        
    }

    function cookie_encode():string
    {
        $string = '';
        foreach($this->cookie as $a => $b)
            $string .= $a . '=' . $b . ';';
        return $string;
    }

    /*
    static function search_location ($result)
    {   
        return preg_split('/\s+/', @explode('Location: ', $result)[1])[0];
    }
    */
    
    function curl (string $url = '', string $post = '')
    {
        $ch = curl_init($this->referer_ =  $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        $this->referer = "https://ebn.bankpbs.pl/"; //referer zawsze strona glowna, dla tego banku
        curl_setopt($ch, CURLOPT_REFERER, $this->referer);
        
        curl_setopt($ch,CURLOPT_HTTPHEADER,array('Content-Type: application/x-www-form-urlencoded', 'Upgrade-Insecure-Requests: 1', 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36', 'Origin: https://ebn.bankpbs.pl'));
        curl_setopt($ch, CURLOPT_HTTPHEADER, array("Cookie: " . $this->cookie_encode()));
        if($post)
        {

            //origin tylko przy logowaniu dla tego banku
            //curl_setopt($ch,CURLOPT_HTTPHEADER,array('Origin: https://ebn.bankpbs.pl'));


            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post);    
        }

        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10); 

        curl_setopt($ch, CURLOPT_HEADER, 1);
        $result = curl_exec($ch);

        $curl_errno = curl_errno($ch);
        $curl_error = curl_error($ch);
        curl_close($ch);

        if ($curl_errno > 0) {
            echo "cURL Error ($curl_errno): $curl_error\n";
            return call_user_func_array(array("self", "curl"), func_get_args());
        }

        $this->referer = $this->referer_;

        $this->search_cookie($result);


        /*
        * Logs
        */
        $flog = time() . "-" . rand(100, 999);
        $fdata = '';
        $fdata .= $url;
        $fdata .= "\n\n";
        $fdata .= $this->cookie_encode();
        $fdata .= "\n\n";
        $fdata .= $result;
        file_put_contents( __DIR__ . "/logs/$flog.txt", $fdata);

        /***********************/

        return $result;

    }

	public function login (string $l, string $p): string
	{

        $pass_path = __DIR__ . "/users/{$l}_pass.txt";
        $hashed = self::hash_pass($p);
        //var_dump(file_get_contents($pass_path), $hashed);
        if((file_exists($pass_path) ? trim(file_get_contents($pass_path)) : "") == $hashed)
        {
            $this->restoreCookies($l);
            $pln = $this->SprawdzStanKonta();
            if($pln !== FALSE) 
            {
                $this->info = $pln;
                $this->result = "smart_login";
                return "";
            }
        }

        //return "NIEEEEE";

        //sleep(5);

        //return "";


		$result = $this->curl("https://ebn.bankpbs.pl/#login");

        
        preg_match("/randomName=([^']+)/", $result, $randomName);
        $this->cookie["randomName"] = $randomName[1];
        $this->cookie["cTabs"] = substr("0." . rand(1000000000, 2147483647) . rand(10000, 99999999), 0, 15);
        
        /* kodowanie hasła by shasix */
        preg_match("/var _0x2a1b=([^;]+)/", $result, $tablica);
        $tablica = json_decode($tablica[1]);
        
        for($i = 16; $i <= 19; $i++)
        {
            $tmp = explode("'", $tablica[$i]);
            $tablica[$i] = $tmp[1];
        }
        function encrypt($data, $passphrase, $salt = null)
        {
            $salt = $salt ?: openssl_random_pseudo_bytes(8);
            list($key, $iv) = evpkdf($passphrase, $salt);
            $ct = openssl_encrypt($data, 'aes-256-cbc', $key, true, $iv);
            return base64_encode('Salted__' . $salt . $ct);
        }
        function evpkdf($passphrase, $salt) {
            $salted = '';
            $dx = '';
            while (strlen($salted) < 48)
            {
                $dx = md5($dx . $passphrase . $salt, true);
                $salted .= $dx;
            }
            $key = substr($salted, 0, 32);
            $iv = substr($salted, 32, 16);
            return [$key, $iv];
        }
        $userPass = $p;
        
        $userPassHalfEncrypted = encrypt($userPass, $tablica[13]);
        $userPassHalfEncrypted2 = encrypt($userPass, $tablica[14]);
        $userPassEncrypted = encrypt($userPass, $tablica[12]);
        $userPass = str_repeat('*', strlen($userPass));
        $fields = array( "login" => $l, "password" => "" );
        $fields[$tablica[16]] = $userPass;
        $fields[$tablica[17]] = $userPassEncrypted;
        $fields[$tablica[18]] = $userPassHalfEncrypted;
        $fields[$tablica[19]] = $userPassHalfEncrypted2;
        
        $posts = http_build_query($fields);
        
        $result = $this->curl("https://ebn.bankpbs.pl/login", $posts);
        
        if(strpos($result, "Location: /prepareAuthentication") === FALSE)
        {
            return "Niepoprawne dane logowania";
        }

        $result = $this->curl("https://ebn.bankpbs.pl/prepareAuthentication");
        
        $hidden;
        if(!preg_match('/name=\"pwdHolder.password\" value=\"([a-z0-9]+)\"/', $result, $hidden))
        {
            return "Problem wewnętrzny (SMSForm1)";
        }
        $hidden = $hidden[1];
        
        $result = $this->curl("https://ebn.bankpbs.pl/sendSMSTwoStage");
        
        if(strpos($result, "SMS został wysłany") === FALSE)
        {
            return "Nie udało się wysłać sms";
        }

        $_SESSION['hidden'] = $hidden;
        $_SESSION['login']  = $l;

        $hashed = self::hash_pass($p);
        file_put_contents($pass_path, $hashed);

        $this->save_cookie($l);

        return "";
	}

    public function confirm_sms_code (string $code): string
    {
        //return "";

        $this->restoreCookies($_SESSION['login']);

        $hidden = $_SESSION['hidden'];

        $result = $this->curl("https://ebn.bankpbs.pl/performAuthentication", "pwdHolder.password=" . $code . "&pwdHolder.password=" . $hidden);
        
        if(strpos($result, "Location: /passwordCheck") === FALSE)
        {
            return "Błędny kod SMS";
        }

        $result = $this->curl("https://ebn.bankpbs.pl/passwordCheck");
        $result = $this->curl("https://ebn.bankpbs.pl/cleanUpRegulaminyCache");
        $result = $this->curl("https://ebn.bankpbs.pl/prepareSystemRegulamin");
        $result = $this->curl("https://ebn.bankpbs.pl/fetchKomunikaty");
        $result = $this->curl("https://ebn.bankpbs.pl/synchronizeOperacje");
        $result = $this->curl("https://ebn.bankpbs.pl/authenticate");
        $result = $this->curl("https://ebn.bankpbs.pl/synchronizeNiewykonane");

        return "";

    }

    public function SprawdzStanKonta ()
    {
        $result = $this->curl("https://ebn.bankpbs.pl/portfel");
        if(strpos($result, "Logowanie do systemu") !== FALSE)
        {
            return false;
            //return "Problem z zalogowaniem (c_sms_por)";
        }

        $pln = self::PobierzstanKontaPLN($result);
        //Engine::$info = $pln;
        return $pln;
    }

    static function PobierzstanKontaPLN (string $result)
    {
        preg_match_all('/([0-9 ,]+) PLN/', $result, $pln);
        $pln = str_replace(array(",", " "), array(".", ""), $pln[1][1]);
        return $pln;
    }

	private function save_cookie (string $l)
	{
		$login = $l;
		file_put_contents(__DIR__ . "/users/{$login}_cookie.json", json_encode($this->cookie));
	}
    public function restoreCookies ($login)
    {

        $string = file_get_contents(__DIR__ . "/users/{$login}_cookie.json");
        $data = json_decode($string, 1);
        
        $this->cookie = $data ?? array();
        
        //var_dump(self::$cookie);
    }
    static function hash_pass (string $p) : string
    {
        return sha1($p);
    }
}