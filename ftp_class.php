<?php
/**
 * PemFTP - A Ftp implementation in pure PHP
 *
 * @package PemFTP
 * @since 2.5
 *
 * @version 1.0
 * @copyright Alexey Dotsenko
 * @author Alexey Dotsenko
 * @link https://www.phpclasses.org/package/1743-PHP-FTP-client-in-pure-PHP.html
 * @license LGPL License https://opensource.org/licenses/lgpl-license.html
 */
if (!defined('CRLF')) define('CRLF', "\r\n");
if (!defined('FTP_AUTOASCII')) define('FTP_AUTOASCII', -1);
if (!defined('FTP_BINARY')) define('FTP_BINARY', 1);
if (!defined('FTP_ASCII')) define('FTP_ASCII', 0);
if (!defined('FTP_FORCE')) define('FTP_FORCE', TRUE);
define('FTP_OS_Unix', 'u');
define('FTP_OS_Windows', 'w');
define('FTP_OS_Mac', 'm');

class ftp_base {
    /* Public variables */
    public $LocalEcho;
    public $Verbose;
    public $OS_local;
    public $OS_remote;
    public $_lastaction;
    public $_timeout;
    public $_passive;
    public $_datahost;
    public $_dataport;
    public $_ftp_control_sock;
    public $_ftp_data_sock;
    public $_ftp_temp_sock;
    public $_ftp_buff_size;
    public $_connected;
    public $_ready;
    public $_code;
    public $_message;
    public $stream;
    public $_eol_code;

    /* Private variables */
    private $_errors;
    private $_type;
    private $_umask;
    private $_host;
    private $_fullhost;
    private $_port;
    private $_login;
    private $_password;
    private $_can_restore;
    private $_port_available;
    private $_curtype;
    private $_features;

    private $_error_array;
    private $AuthorizedTransferMode;
    private $OS_FullName;
    private $AutoAsciiExt;

    /* Constructor */
    // Removed to support strict mode (non-original author modification)
    // function ftp_base($port_mode=FALSE) {
    // 	$this->__construct($port_mode);
    // }

	public function __construct($port_mode=FALSE, $verb=FALSE, $le=FALSE) {
        $this->LocalEcho = $le;
        $this->Verbose = $verb;
        $this->_lastaction = NULL;
        $this->_error_array = array();
        $this->_eol_code = array(FTP_OS_Unix => "\n", FTP_OS_Mac => "\r", FTP_OS_Windows => "\r\n");
        $this->AuthorizedTransferMode = array(FTP_AUTOASCII, FTP_ASCII, FTP_BINARY);
        $this->OS_FullName = array(FTP_OS_Unix => 'UNIX', FTP_OS_Windows => 'WINDOWS', FTP_OS_Mac => 'MACOS');
        $this->AutoAsciiExt = array('ASP', 'BAT', 'C', 'CPP', 'CSS', 'CSV', 'JS', 'H', 'HTM', 'HTML', 'SHTML', 'INI', 'LOG', 'PHP', 'PHTML', 'PL', 'PERL', 'SH', 'SQL', 'TXT');
        $this->_port_available = ($port_mode == TRUE);
        $this->SendMSG('Staring FTP client class' . ($this->_port_available ? '' : ' without PORT mode support'));
        $this->_connected = FALSE;
        $this->_ready = FALSE;
        $this->_can_restore = FALSE;
        $this->_code = 0;
        $this->_message = '';
        $this->_ftp_buff_size = 4096;
        $this->_curtype = NULL;
        $this->SetUmask(0022);
        $this->SetType(FTP_AUTOASCII);
        $this->SetTimeout(30);
        $this->Passive(!$this->_port_available);
        $this->_login = 'anonymous';
        $this->_password = 'anon@ftp.com';
        $this->_features = array();
        $this->OS_local = FTP_OS_Unix;
        $this->OS_remote = FTP_OS_Unix;
        $this->features = array();
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') $this->OS_local = FTP_OS_Windows;
        elseif (strtoupper(substr(PHP_OS, 0, 3)) === 'MAC') $this->OS_local = FTP_OS_Mac;
    }

// <!-- --------------------------------------------------------------------------------------- -->
// <!--       Public functions                                                                  -->
// <!-- --------------------------------------------------------------------------------------- -->
	public function last_message() {
        return $this->_message;
    }

	public function parselisting($list) {
//	Parses 1 line like:		'drwxrwx---  2 owner group 4096 Apr 23 14:57 text'
        if (preg_match('/^([-ld])([rwxst-]+)\s+(\d+)\s+([^\s]+)\s+([^\s]+)\s+(\d+)\s+(\w{3})\s+(\d+)\s+([\:\d]+)\s+(.+)$/i', $list, $ret)) {
            $v = array(
                'type' => ($ret[1] == '-' ? 'f' : $ret[1]),
                'perms' => 0,
                'inode' => $ret[3],
                'owner' => $ret[4],
                'group' => $ret[5],
                'size' => $ret[6],
                'date' => $ret[7] . ' ' . $ret[8] . ' ' . $ret[9],
                'name' => $ret[10]
            );
            $bad = array('(?)');
            if (in_array($v['owner'], $bad)) $v['owner'] = NULL;
            if (in_array($v['group'], $bad)) $v['group'] = NULL;
            $v['perms'] += 00400 * (int)($ret[2]{0} === 'r');
            $v['perms'] += 00200 * (int)($ret[2]{1} === 'w');
            $v['perms'] += 00100 * (int)in_array($ret[2]{2}, array('x', 's'));
            $v['perms'] += 00040 * (int)($ret[2]{3} === 'r');
            $v['perms'] += 00020 * (int)($ret[2]{4} === 'w');
            $v['perms'] += 00010 * (int)in_array($ret[2]{5}, array('x', 's'));
            $v['perms'] += 00004 * (int)($ret[2]{6} === 'r');
            $v['perms'] += 00002 * (int)($ret[2]{7} === 'w');
            $v['perms'] += 00001 * (int)in_array($ret[2]{8}, array('x', 't'));
            $v['perms'] += 04000 * (int)in_array($ret[2]{2}, array('S', 's'));
            $v['perms'] += 02000 * (int)in_array($ret[2]{5}, array('S', 's'));
            $v['perms'] += 01000 * (int)in_array($ret[2]{8}, array('T', 't'));
        }
        return $v;
    }

    public function SendMSG($message = '', $crlf=true) {
        if ($this->Verbose) {
            echo $message . ($crlf ? CRLF : '');
            flush();
        }
        return TRUE;
    }

	public function SetType($mode=FTP_AUTOASCII) {
        if (!in_array($mode, $this->AuthorizedTransferMode)) {
            $this->SendMSG('Wrong type');
            return FALSE;
        }
        $this->_type = $mode;
        $this->SendMSG('Transfer type: ' . ($this->_type == FTP_BINARY ? 'binary' : ($this->_type == FTP_ASCII ? 'ASCII' : 'auto ASCII')));
        return TRUE;
    }

	public function _settype($mode=FTP_ASCII) {
        if ($this->_ready) {
            if ($mode == FTP_BINARY) {
                if ($this->_curtype != FTP_BINARY) {
                    if (!$this->_exec('TYPE I', 'SetType')) return FALSE;
                    $this->_curtype = FTP_BINARY;
                }
            } elseif ($this->_curtype != FTP_ASCII) {
                if (!$this->_exec('TYPE A', 'SetType')) return FALSE;
                $this->_curtype = FTP_ASCII;
            }
        } else return FALSE;
        return TRUE;
    }

	public function Passive($pasv=NULL) {
        if (is_null($pasv)) $this->_passive = !$this->_passive;
        else $this->_passive = $pasv;
        if (!$this->_port_available && !$this->_passive) {
            $this->SendMSG('Only passive connections available!');
            $this->_passive = TRUE;
            return FALSE;
        }
        $this->SendMSG('Passive mode ' . ($this->_passive ? 'on' : 'off'));
        return TRUE;
    }

	public function SetServer($host, $port=21, $reconnect=true) {
        if (!is_int($port)) {
            $this->verbose = true;
            $this->SendMSG('Incorrect port syntax');
            return FALSE;
        } else {
            $ip = @gethostbyname($host);
            $dns = @gethostbyaddr($host);
            if (!$ip) $ip = $host;
            if (!$dns) $dns = $host;
            if (ip2long($ip) === -1) {
                $this->SendMSG(sprintf('Wrong host name/address "%s"', $host));
                return FALSE;
            }
            $this->_host = $ip;
            $this->_fullhost = $dns;
            $this->_port = $port;
            $this->_dataport = $port - 1;
        }
        $this->SendMSG(sprintf('Host "%s(%s):%s"', $this->_fullhost, $this->_host, $this->_port));
        if ($reconnect) {
            if ($this->_connected) {
                $this->SendMSG('Reconnecting');
                if (!$this->quit(FTP_FORCE)) return FALSE;
                if (!$this->connect()) return FALSE;
            }
        }
        return TRUE;
    }

	public function SetUmask($umask=0022) {
        $this->_umask = $umask;
        umask($this->_umask);
        $this->SendMSG('UMASK 0' . decoct($this->_umask));
        return TRUE;
    }

	public function SetTimeout($timeout=30) {
        $this->_timeout = $timeout;
        $this->SendMSG('Timeout ' . $this->_timeout);
        if ($this->_connected)
            if (!$this->_settimeout($this->_ftp_control_sock)) return FALSE;
        return TRUE;
    }

	public function connect($server=NULL) {
        if (!empty($server)) {
            if (!$this->SetServer($server)) return false;
        }
        if ($this->_ready) return true;
        $this->SendMsg('Local OS : ' . $this->OS_FullName[$this->OS_local]);
        if (!($this->_ftp_control_sock = $this->_connect($this->_host, $this->_port))) {
            $this->SendMSG(
                sprintf(
                    "Error : Can't connect to remote host '%s :%s'",
                    $this->_fullhost,
                    $this->_port
                )
            );
            return FALSE;
        }
        $this->SendMSG(
            sprintf(
                "Connected to remote host '%s:%s'. Waiting for greeting.",
                $this->_fullhost,
                $this->_port
            )
        );
        do {
            if (!$this->_readmsg()) return FALSE;
            if (!$this->_checkCode()) return FALSE;
            $this->_lastaction = time();
        } while ($this->_code < 200);
        $this->_ready = true;
        $syst = $this->systype();
        if (!$syst) $this->SendMSG("Can't detect remote OS");
        else {
            if (preg_match('/win|dos|novell/i', $syst[0])) $this->OS_remote = FTP_OS_Windows;
            elseif (preg_match('/os/i', $syst[0])) $this->OS_remote = FTP_OS_Mac;
            elseif (preg_match('/(li|u)nix/i', $syst[0])) $this->OS_remote = FTP_OS_Unix;
            else $this->OS_remote = FTP_OS_Mac;
            $this->SendMSG('Remote OS: ' . $this->OS_FullName[$this->OS_remote]);
        }
        if (!$this->features()) $this->SendMSG("Can't get features list. All supported - disabled");
        else $this->SendMSG('Supported features: ' . implode(', ', array_keys($this->_features)));
        return TRUE;
    }

	public function quit($force=false) {
        if ($this->_ready) {
            if (!$this->_exec('QUIT') && !$force) return FALSE;
            if (!$this->_checkCode() && !$force) return FALSE;
            $this->_ready = false;
            $this->SendMSG('Session finished');
        }
        $this->_quit();
        return TRUE;
    }

	public function login($user=NULL, $pass=NULL) {
        if (!is_null($user)) $this->_login = $user;
        else $this->_login = 'anonymous';
        if (!is_null($pass)) $this->_password = $pass;
        else $this->_password = 'anon@anon.com';
        if (!$this->_exec('USER ' . $this->_login, 'login')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        if ($this->_code != 230) {
            if (!$this->_exec((($this->_code == 331) ? 'PASS ' : 'ACCT ') . $this->_password, 'login')) return FALSE;
            if (!$this->_checkCode()) return FALSE;
        }
        $this->SendMSG('Authentication succeeded');
        if (empty($this->_features)) {
            if (!$this->features()) $this->SendMSG("Can't get features list. All supported - disabled");
            else $this->SendMSG('Supported features: ' . implode(', ', array_keys($this->_features)));
        }
        return TRUE;
    }

	public function pwd() {
        if (!$this->_exec('PWD', 'pwd')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return ereg_replace("^[0-9]{3} \"(.+)\" .+" . CRLF, "\\1", $this->_message);
    }

	public function cdup() {
        if (!$this->_exec('CDUP', 'cdup')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return true;
    }

	public function chdir($pathname) {
        if (!$this->_exec('CWD ' . $pathname, 'chdir')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return TRUE;
    }

	public function rmdir($pathname) {
        if (!$this->_exec('RMD ' . $pathname, 'rmdir')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return TRUE;
    }

	public function mkdir($pathname) {
        if (!$this->_exec('MKD ' . $pathname, 'mkdir')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return TRUE;
    }

	public function rename($from, $to) {
        if (!$this->_exec('RNFR ' . $from, 'rename')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        if ($this->_code == 350) {
            if (!$this->_exec('RNTO ' . $to, 'rename')) return FALSE;
            if (!$this->_checkCode()) return FALSE;
        } else return FALSE;
        return TRUE;
    }

	public function filesize($pathname) {
        if (!isset($this->_features['SIZE'])) {
            $this->PushError('filesize', 'not supported by server');
            return FALSE;
        }
        if (!$this->_exec('SIZE ' . $pathname, 'filesize')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return ereg_replace("^[0-9]{3} ([0-9]+)" . CRLF, "\\1", $this->_message);
    }

	public function abort() {
        if (!$this->_exec('ABOR', 'abort')) return FALSE;
        if (!$this->_checkCode()) {
            if ($this->_code != 426) return FALSE;
            if (!$this->_readmsg('abort')) return FALSE;
            if (!$this->_checkCode()) return FALSE;
        }
        return true;
    }

	public function mdtm($pathname) {
        if (!isset($this->_features['MDTM'])) {
            $this->PushError('mdtm', 'not supported by server');
            return FALSE;
        }
        if (!$this->_exec('MDTM ' . $pathname, 'mdtm')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        $mdtm = ereg_replace('^[0-9]{3} ([0-9]+)' . CRLF, "\\1", $this->_message);
        $date = sscanf($mdtm, '%4d%2d%2d%2d%2d%2d');
        $timestamp = mktime($date[3], $date[4], $date[5], $date[1], $date[2], $date[0]);
        return $timestamp;
    }

	public function systype() {
        if (!$this->_exec('SYST', 'systype')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        $DATA = explode(' ', $this->_message);
        return array($DATA[1], $DATA[3]);
    }

	public function delete($pathname) {
        if (!$this->_exec('DELE ' . $pathname, 'delete')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return TRUE;
    }

    public function site($command, $fnction='site') {
        if (!$this->_exec('SITE ' . $command, $fnction)) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return TRUE;
    }

	public function chmod($pathname, $mode) {
        if (!$this->site('CHMOD ' . decoct($mode) . ' ' . $pathname, 'chmod')) return FALSE;
        return TRUE;
    }

	public function restore($from) {
        if (!isset($this->_features['REST'])) {
            $this->PushError('restore', 'not supported by server');
            return FALSE;
        }
        if ($this->_curtype != FTP_BINARY) {
            $this->PushError('restore', "can't restore in ASCII mode");
            return FALSE;
        }
        if (!$this->_exec('REST ' . $from, 'resore')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return TRUE;
    }

    public function features() {
        if (!$this->_exec('FEAT', 'features')) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        $f = array_slice(preg_split('/[' . CRLF . ']+/', $this->_message, -1, PREG_SPLIT_NO_EMPTY), 1, -1);
        array_walk(
            $f,
            create_function(
                '&$a',
                '$a=preg_replace(\'/[0-9]{3}[\s-]+/\', \'\', trim($a));\'));'
            )
        );
        $this->_features = array();
        foreach ($f as $k => $v) {
            $v = explode(' ', trim($v));
            $this->_features[array_shift($v)] = $v;
        }
        return true;
    }

    public function rawlist($pathname='', $arg='') {
        return $this->_list(($arg ? ' ' . $arg : '') . ($pathname ? ' ' . $pathname : ''), 'LIST', 'rawlist');
    }

    public function nlist($pathname='', $arg='') {
        return $this->_list(($arg ? ' ' . $arg : '') . ($pathname ? ' ' . $pathname : ''), 'NLST', 'nlist');
    }

	function is_exists($pathname) {
        return $this->file_exists($pathname);
    }

	public function file_exists($pathname) {
        $exists = true;
        if (!$this->_exec('RNFR ' . $pathname, 'rename')) $exists = FALSE;
        else {
            if (!$this->_checkCode()) $exists = FALSE;
            $this->abort();
        }
        if ($exists) $this->SendMSG('Remote file ' . $pathname . ' exists');
        else $this->SendMSG('Remote file ' . $pathname . ' does not exist');
        return $exists;
    }

	public function get($remotefile, $localfile=NULL, $rest=0) {
        if (is_null($localfile)) $localfile = $remotefile;
        if (@file_exists($localfile)) $this->SendMSG('Warning : local file will be overwritten');
        $fp = @fopen($localfile, 'w');
        if (!$fp) {
            $this->PushError('get', "can't open local file", "Can't create \"" . $localfile . "\"");
            return FALSE;
        }
        if ($this->_can_restore && $rest != 0) fseek($fp, $rest);
        $pi = pathinfo($remotefile);
        if ($this->_type == FTP_ASCII || ($this->_type == FTP_AUTOASCII && in_array(strtoupper($pi['extension']), $this->AutoAsciiExt))) $mode = FTP_ASCII;
        else $mode = FTP_BINARY;
        if (!$this->_data_prepare($mode)) {
            fclose($fp);
            return FALSE;
        }
        if ($this->_can_restore && $rest != 0) $this->restore($rest);
        if (!$this->_exec('RETR ' . $remotefile, 'get')) {
            $this->_data_close();
            fclose($fp);
            return FALSE;
        }
        if (!$this->_checkCode()) {
            $this->_data_close();
            fclose($fp);
            return FALSE;
        }
        $out = $this->_data_read($mode, $fp);
        fclose($fp);
        $this->_data_close();
        if (!$this->_readmsg()) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return $out;
    }

	public function put($localfile, $remotefile=NULL, $rest=0) {
        if (is_null($remotefile)) $remotefile = $localfile;
        if (!@file_exists($localfile)) {
            $this->PushError(
                'put',
                "can't open local file",
                sprintf('No such file or directory "%s"', $localfile)
            );
            return FALSE;
        }
        $fp = @fopen($localfile, 'r');

        if (!$fp) {
            $this->PushError('put', "can't open local file", "Can't read file '{$localfile}'");
            return FALSE;
        }
        if ($this->_can_restore && $rest != 0) fseek($fp, $rest);
        $pi = pathinfo($localfile);
        if ($this->_type == FTP_ASCII || ($this->_type == FTP_AUTOASCII && in_array(strtoupper($pi['extension']), $this->AutoAsciiExt))) $mode = FTP_ASCII;
        else $mode = FTP_BINARY;
        if (!$this->_data_prepare($mode)) {
            fclose($fp);
            return FALSE;
        }
        if ($this->_can_restore && $rest != 0) $this->restore($rest);
        if (!$this->_exec('STOR ' . $remotefile, 'put')) {
            $this->_data_close();
            fclose($fp);
            return FALSE;
        }
        if (!$this->_checkCode()) {
            $this->_data_close();
            fclose($fp);
            return FALSE;
        }
        $ret = $this->_data_write($mode, $fp);
        fclose($fp);
        $this->_data_close();
        if (!$this->_readmsg()) return FALSE;
        if (!$this->_checkCode()) return FALSE;
        return $ret;
    }

    public function mput($local='.', $remote=NULL, $continious=false) {
        $local = realpath($local);
        if (!@file_exists($local)) {
            $this->PushError('mput', "can't open local folder", 'Cannot stat folder "' . $local . '"');
            return FALSE;
        }
        if (!is_dir($local)) return $this->put($local, $remote);
        if (empty($remote)) $remote = '.';
        elseif (!$this->file_exists($remote) && !$this->mkdir($remote)) return FALSE;
        if ($handle = opendir($local)) {
            $list = array();
            while (false !== ($file = readdir($handle))) {
                if ($file !== '.' && $file !== '..') $list[] = $file;
            }
            closedir($handle);
        } else {
            $this->PushError('mput', "can't open local folder", 'Cannot read folder "' . $local . '"');
            return FALSE;
        }
        if (empty($list)) return TRUE;
        $ret = true;
        foreach ($list as $el) {
            if (is_dir($local . '/' . $el)) $t = $this->mput($local . '/' . $el, $remote . '/' . $el);
            else $t = $this->put($local . '/' . $el, $remote . '/' . $el);
            if (!$t) {
                $ret = FALSE;
                if (!$continious) break;
            }
        }
        return $ret;

    }

    public function mget($remote, $local='.', $continious=false) {
        $list = $this->rawlist($remote, '-lA');
        if ($list === false) {
            $this->PushError('mget', "can't read remote folder list", 'Can\'t read remote folder "' . $remote . '" contents');
            return FALSE;
        }
        if (empty($list)) return true;
        if (!@file_exists($local)) {
            if (!@mkdir($local)) {
                $this->PushError('mget', "can't create local folder", "Can't create folder \"" . $local . '"');
                return FALSE;
            }
        }
        foreach ($list as $k => $v) {
            $list[$k] = $this->parselisting($v);
            if ($list[$k]['name'] === '.' || $list[$k]['name'] === '..') unset($list[$k]);
        }
        $ret = true;
        foreach ($list as $el) {
            if ($el['type'] === 'd') {
                if (!$this->mget($remote . '/' . $el['name'], $local . '/' . $el['name'], $continious)) {
                    $this->PushError('mget', "can't copy folder", "Can't copy remote folder \"" . $remote . '/' . $el["name"] . "\" to local \"" . $local . "/" . $el['name'] . "\"");
                    $ret = false;
                    if (!$continious) break;
                }
            } else {
                if (!$this->get($remote . '/' . $el['name'], $local . '/' . $el['name'])) {
                    $this->PushError('mget', "can't copy file", "Can't copy remote file \"" . $remote . '/' . $el['name'] . "\" to local \"" . $local . "/" . $el['name'] . "\"");
                    $ret = false;
                    if (!$continious) break;
                }
            }
            @chmod($local . '/' . $el['name'], $el['perms']);
            $t = strtotime($el['date']);
            if ($t !== -1 && $t !== false) @touch($local . '/' . $el['name'], $t);
        }
        return $ret;
    }

	public function mdel($remote, $continious=false) {
        $list = $this->rawlist($remote, '-la');
        if ($list === false) {
            $this->PushError('mdel', "can't read remote folder list", "Can't read remote folder \"" . $remote . "\" contents");
            return false;
        }

        foreach ($list as $k => $v) {
            $list[$k] = $this->parselisting($v);
            if ($list[$k]['name'] === '.' || $list[$k]['name'] === '..') unset($list[$k]);
        }
        $ret = true;

        foreach ($list as $el) {
            if ($el['type'] === 'd') {
                if (!$this->mdel($remote . '/' . $el['name'], $continious)) {
                    $ret = false;
                    if (!$continious) break;
                }
            } else {
                if (!$this->delete($remote . '/' . $el['name'])) {
                    $this->PushError('mdel', "can't delete file", "Can't delete remote file \"" . $remote . '/' . $el['name'] . "\"");
                    $ret = false;
                    if (!$continious) break;
                }
            }
        }

        if (!$this->rmdir($remote)) {
            $this->PushError('mdel', "can't delete folder", "Can't delete remote folder \"" . $remote . "/" . $el['name'] . "\"");
            $ret = false;
        }
        return $ret;
    }

	public function mmkdir($dir, $mode = 0777) {
        if (empty($dir)) return FALSE;
        if ($this->is_exists($dir) || $dir === '/') return TRUE;
        if (!$this->mmkdir(dirname($dir), $mode)) return false;
        $r = $this->mkdir($dir, $mode);
        $this->chmod($dir, $mode);
        return $r;
    }

	public function glob($pattern, $handle=NULL) {
        $path = $output = null;
        if (PHP_OS === 'WIN32') $slash = '\\';
        else $slash = '/';
        $lastpos = strrpos($pattern, $slash);
        if (!($lastpos === false)) {
            $path = substr($pattern, 0, -$lastpos - 1);
            $pattern = substr($pattern, $lastpos);
        } else $path = getcwd();
        if (is_array($handle) && !empty($handle)) {
            while ($dir = each($handle)) {
                if ($this->glob_pattern_match($pattern, $dir))
                    $output[] = $dir;
            }
        } else {
            $handle = @opendir($path);
            if ($handle === false) return false;
            while ($dir = readdir($handle)) {
                if ($this->glob_pattern_match($pattern, $dir))
                    $output[] = $dir;
            }
            closedir($handle);
        }
        if (is_array($output)) return $output;
        return false;
    }

	public function glob_pattern_match($pattern, $string) {
        $out = null;
        $chunks = explode(';', $pattern);
        foreach ($chunks as $chunk) {
            $escape = array('$', '^', '.', '{', '}', '(', ')', '[', ']', '|');
            while (strpos($chunk, '**') !== false)
                $chunk = str_replace('**', '*', $chunk);
            foreach ($escape as $probe)
                $chunk = str_replace($probe, "\\$probe", $chunk);
            $chunk = str_replace('?*', '*',
                str_replace('*?', '*',
                    str_replace('*', '.*',
                        str_replace('?', '.{1,1}', $chunk))));
            $out[] = $chunk;
        }
        if (count($out) == 1) return ($this->glob_regexp("^$out[0]$", $string));
        else {
            foreach ($out as $tester)
                if ($this->my_regexp("^$tester$", $string)) return true;
        }
        return false;
    }

	public function glob_regexp($pattern, $probe) {
        $sensitive = (PHP_OS !== 'WIN32');
        return ($sensitive ?
            ereg($pattern, $probe) :
            eregi($pattern, $probe)
        );
    }
// <!-- --------------------------------------------------------------------------------------- -->
// <!--       Private functions                                                                 -->
// <!-- --------------------------------------------------------------------------------------- -->
	public function _checkCode() {
        return ($this->_code < 400 && $this->_code > 0);
    }

    public function _list($arg='', $cmd='LIST', $fnction='_list') {
        if (!$this->_data_prepare()) return false;
        if (!$this->_exec($cmd . $arg, $fnction)) {
            $this->_data_close();
            return FALSE;
        }
        if (!$this->_checkCode()) {
            $this->_data_close();
            return FALSE;
        }
        $out = '';
        if ($this->_code < 200) {
            $out = $this->_data_read();
            $this->_data_close();
            if (!$this->_readmsg()) return FALSE;
            if (!$this->_checkCode()) return FALSE;
            if ($out === FALSE) return FALSE;
            $out = preg_split('/[' . CRLF . ']+/', $out, -1, PREG_SPLIT_NO_EMPTY);
//			$this->SendMSG(implode($this->_eol_code[$this->OS_local], $out));
        }
        return $out;
    }

// <!-- --------------------------------------------------------------------------------------- -->
// <!-- Partie : gestion des erreurs                                                            -->
// <!-- --------------------------------------------------------------------------------------- -->
// Generates an error for processing external to the class
	public function PushError($fctname, $msg, $desc=false){
        $error = array();
        $error['time'] = time();
        $error['fctname'] = $fctname;
        $error['msg'] = $msg;
        $error['desc'] = $desc;
        if ($desc) $tmp = ' (' . $desc . ')'; else $tmp = '';
        $this->SendMSG($fctname . ': ' . $msg . $tmp);
        return (array_push($this->_error_array, $error));
    }

// Recover an external error
	public function PopError(){
        if (count($this->_error_array)) return (array_pop($this->_error_array));
        else return (false);
    }
}

$mod_sockets = TRUE;
if (!extension_loaded('sockets')) {
    $prefix = (PHP_SHLIB_SUFFIX === 'dll') ? 'php_' : '';
    if (!@dl($prefix . 'sockets.' . PHP_SHLIB_SUFFIX)) $mod_sockets = FALSE;
}

require_once 'ftp_class_' . ($mod_sockets ? 'sockets' : 'pure') . '.php';
