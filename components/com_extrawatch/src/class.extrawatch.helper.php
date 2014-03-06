<?php

/**
 * @file
 * ExtraWatch - A real-time ajax monitor and live stats  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @package ExtraWatch  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @version 2.2  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @revision 1597  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @license http://www.gnu.org/licenses/gpl-3.0.txt     GNU General Public License v3  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @copyright (C) 2014 by CodeGravity.com - All rights reserved!  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @website http://www.extrawatch.com  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 */

defined('_JEXEC') or die('Restricted access');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

class ExtraWatchHelper  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
{

    public $env;
    public $database;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    public $config;

    const DEFAULT_TRUNC_LENGTH = 60;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    const _EW_ENCRYPTED = "#encrypted#";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

    function __construct($database)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $this->env = ExtraWatchEnvFactory::getEnvironment();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $this->database = $database;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $this->config = new ExtraWatchConfig($this->database);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * helper
     */
    function getIP2LocationURL($ip)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $url = $this->config->getConfigValue('EXTRAWATCH_TOOLTIP_URL');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $result = str_replace("{ip}", $ip, $url);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        //TODO : appears to be a bug in str_ireplace - doesn't work!  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return $result;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * helper
     */
    function resetData()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {

        foreach (unserialize(EXTRAWATCH_TABLES_TO_TRUNCATE) as $table) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $query = sprintf("DELETE FROM `$table`");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $this->database->executeQuery($query);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        return TRUE;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }


    /**
     * helper
     *
     * @return unknown  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @deprecated
     */
    function getURI()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $redirURI = addslashes(@strip_tags(@ $_SERVER[$this->config->getConfigValue('EXTRAWATCH_SERVER_URI_KEY')]));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $uri = ExtraWatchHelper::htmlspecialchars(addslashes(@strip_tags(@ $_SERVER['REQUEST_URI'])));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

        if (@ $redirURI && @ substr($redirURI, -9, 9) != "index.php")  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $uri = $redirURI;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

        return $uri;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * helper
     */
    static function truncate($str, $len = ExtraWatchHelper::DEFAULT_TRUNC_LENGTH)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        if (strlen($str) < $len)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            return $str;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        else
            return substr($str, 0, $len) . "...";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * config
     */
    function saveSettings($post)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $this->config->saveConfigValues(unserialize(EXTRAWATCH_CHECKBOX_NAMES_ARRAY), $post);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return TRUE;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }


    static function getUser($env)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        return $env->getCurrentUser();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    static function getAdminEmail($env)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        return $env->getAdminEmail();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    function getUsername()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $user = & ExtraWatchHelper::getUser($this->env);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return $user->getUsername();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }


    /**
     * helper
     */
    // fnmatch PHP function only on UNIX :(, this replaces the wildcard search  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    static function wildcardSearch($pattern, $string)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        return preg_match("#^" . strtr(preg_quote($pattern, '#'), array(  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            '\*' => '.*',  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            '\?' => '.'  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        )) . "$#i", $string);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }


    /**
     * helper
     */
    function getTooltipOnClick()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        return $this->config->getCheckboxValue("EXTRAWATCH_TOOLTIP_ONCLICK");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * helper
     * @return unknown  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     */
    function getTooltipOnEvent()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        if ($this->getTooltipOnClick()) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            return "title='" . _EW_TOOLTIP_CLICK . "' onclick";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        } else {
            return "title='" . _EW_TOOLTIP_MOUSE_OVER . "' onmouseover";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
    }

    /**
     * helper
     */
    function getTooltipOnEventHide()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        if (!$this->getTooltipOnClick()) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            return "onClick='ajax_hideTooltip();refreshStats();'";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        return;
    }

    /**
     * helper
     * @return unknown  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     */
    function getAvailableLanguages()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $langDirPath = JPATH_BASE2 . DS . "components" . DS . "com_extrawatch" . DS . "lang";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

        if ($handle = @ opendir($langDirPath)) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            while (FALSE !== ($file = readdir($handle))) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                if (strstr($file, ".php")) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    $file = str_replace(".php", "", $file);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    $langArray[] = $file;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                }
            }
            closedir($handle);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        sort($langArray);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return @ $langArray;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    function countryByIpCached($ip)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $query = sprintf("select countryCode from #__extrawatch_ip2c_cache where (ip = '%s') limit 1", $this->database->getEscaped($ip));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return $this->database->resultQuery($query);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    function insertCountryByIpCached($ip, $countryCode)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $query = sprintf("insert IGNORE into #__extrawatch_ip2c_cache (ip, countryCode) values ('%s','%s')", $this->database->getEscaped($ip), $this->database->getEscaped($countryCode));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return $this->database->executeQuery($query);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * helper
     */
    function countryByIp($ip)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {

        if ($ip == '127.0.0.1') {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            return;
        }
        $countryCached = $this->countryByIpCached($ip);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        if (@$countryCached) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            return $countryCached;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
		
        $query = sprintf("select ip, country from #__extrawatch where (ip = '%s' and country is not NULL) limit 1", $this->database->getEscaped($ip));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $row3 = $this->database->resultQuery($query);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

        if (@ !$row3->country) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

            $iplook = new ExtraWatchIP2Country($ip);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $iplook->UseDB = TRUE;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            if (_EW_CLOUD_MODE) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $tablePrefix = _EW_GLOBAL_TABLE_PREFIX."_";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            } else {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $tablePrefix = $this->env->getDbPrefix();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            }
			
            $iplook->db_tablename = $tablePrefix."extrawatch_ip2c";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

            if (($iplook->LookUp())) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $country = strtolower($iplook->Country);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $this->insertCountryByIpCached($ip, $country);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            } else {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $country = EXTRAWATCH_UNKNOWN_COUNTRY;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            }

            $query3 = sprintf("update #__extrawatch set country = '%s' where ip = '%s'", $this->database->getEscaped($country), $this->database->getEscaped($ip));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $this->database->executeQuery($query3);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

        } else {
            $country = $row3->country;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }

        return @ $country;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * helper
     */
    function countryCodeToCountryName($code)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $query = sprintf("select country from #__extrawatch_cc2c where cc = '%s' limit 1", $this->database->getEscaped($code));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $countryName = $this->database->resultQuery($query);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return $countryName;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }


    /**
     * helper
     */
    function countryCodeToCountryNameList()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $query = sprintf("select cc, country from #__extrawatch_cc2c");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $result = $this->database->assocListQuery($query);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $assocArrayResult = array();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		if (@$result)
        foreach($result as $object) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $assocArrayResult[$object['cc']] = $object['country'];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        return $assocArrayResult;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    function removeRepetitiveTitle($title)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        if ($this->config->getCheckboxValue("EXTRAWATCH_HIDE_REPETITIVE_TITLE")) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $title = str_replace($this->env->getTitle(), "", $title);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        return $title;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }


    /**
     * filtering input get var  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @param  $key
     * @return mixed  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     */
    static function requestGet($key = null)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        if (isset($key)) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            //print_r(ExtraWatchEnvFactory::getEnvironment());  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            return @strip_tags(ExtraWatchEnvFactory::getEnvironment()->getRequest()->getVar($key));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        } else {
            $getArray = ExtraWatchEnvFactory::getEnvironment()->getRequest()->get('get');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            if (@$getArray)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            foreach ($getArray as &$get) { /* traversing the array and stripping tags */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $get = @strip_tags($get);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            }
            return $getArray;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
    }

    static function request($key = null)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $value = ExtraWatchHelper::requestGet($key);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        if (!$value) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $value = ExtraWatchHelper::requestPost($key);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        return $value;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * Filtering input post var  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @param  $key
     * @return mixed  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     */
    static function requestPost($key = null)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        if (isset($key)) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            return ExtraWatchEnvFactory::getEnvironment()->getRequest()->getVar($key);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        } else {
            $postArray = @ExtraWatchEnvFactory::getEnvironment()->getRequest()->get('post');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            if (@$postArray)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            foreach ($postArray as &$post) { /* traversing the array and stripping tags */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                if (is_array($post)) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    foreach ($post as &$postNested) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                        $postNested = @strip_tags($postNested);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    }  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                } else {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    $post = @strip_tags($post);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                }
            }
            return $postArray;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }

    }

    /**
     * sender
     *
     * @param  $recipient  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @param  $sender  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @param  $subject  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @param  $body  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @return void
     */
    function sendEmail(&$env, $recipient, $sender, $subject, $body, $bcc = "")  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $body = ("<html><body>" . $body . "</body></html>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $cc = $bcc = $attachment = $replyto = $replytoname = "";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $env->sendMail($recipient, $sender, $recipient, $subject, $body, 1, $cc, $bcc, $attachment, $replyto, $replytoname);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * Config
     * @param  $post  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @return bool
     */
    function saveAntiSpamSettings($post)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {

        $checkboxNamesArray = array(  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            'EXTRAWATCH_SPAMWORD_BANS_ENABLED'  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        );

        $this->config->saveConfigValues($checkboxNamesArray, $post);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return TRUE;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * Config
     * @param  $post  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @return bool
     */
    function saveEmailSettings($post)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {

        $checkboxNamesArray = array(  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            'EXTRAWATCH_EMAIL_REPORTS_ENABLED',  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            'EXTRAWATCH_EMAIL_SEO_REPORTS_ENABLED'  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        );

        $this->config->saveConfigValues($checkboxNamesArray, $post);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return TRUE;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * Config
     * @param  $post  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @return bool
     */
    function saveSEOSettings($post)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {

        $checkboxNamesArray = array(  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            'EXTRAWATCH_SEO_RENDER_ONLY_CHANGED',  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            'EXTRAWATCH_SEO_LIST_ENCRYPTED_KEYWORDS',  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            'EXTRAWATCH_SEO_SHOW_ALL_TIME_REPORT'  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        );

        $this->config->saveConfigValues($checkboxNamesArray, $post);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return TRUE;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    /**
     * Config
     * @param  $post  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @return bool
     */
    function saveUserSettings($post)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {

        $checkboxNamesArray = array(  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            'EXTRAWATCH_USERS_SEND_ALERT_EMAILS'  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        );

        $this->config->saveConfigValues($checkboxNamesArray, $post);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return TRUE;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }


    // HSV Values:Number 0-1  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    static function HSV_TO_RGB($H, $S, $V)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    { // RGB Results:Number 0-255  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $RGB = array();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

        if ($S == 0) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $R = $G = $B = $V * 255;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        else
        {
            $var_H = $H * 6;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $var_i = floor($var_H);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $var_1 = $V * (1 - $S);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $var_2 = $V * (1 - $S * ($var_H - $var_i));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $var_3 = $V * (1 - $S * (1 - ($var_H - $var_i)));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

            if ($var_i == 0) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_R = $V;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_G = $var_3;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_B = $var_1;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            }
            elseif ($var_i == 1) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_R = $var_2;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_G = $V;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_B = $var_1;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            }
            elseif ($var_i == 2) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_R = $var_1;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_G = $V;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_B = $var_3;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            }
            elseif ($var_i == 3) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_R = $var_1;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_G = $var_2;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_B = $V;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            }
            elseif ($var_i == 4) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_R = $var_3;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_G = $var_1;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_B = $V;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            }
            else {
                $var_R = $V;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_G = $var_1;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $var_B = $var_2;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            }

            $R = $var_R * 255;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $G = $var_G * 255;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $B = $var_B * 255;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }

        $RGB['R'] = floor($R);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $RGB['G'] = floor($G);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $RGB['B'] = floor($B);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

        return $RGB;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    static function hueFromRatio($ratio)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $offset = 1 / 4;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return 1 - ($ratio * 3 / 4 + $offset);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    static function rgbFromRatio($ratio)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        $hue = ExtraWatchHelper::hueFromRatio($ratio);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $rgb = ExtraWatchHelper::HSV_TO_RGB($hue, 1, 1);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $rgbString = "rgb(" . $rgb['R'] . ", " . $rgb['G'] . ", " . $rgb['B'] . ")";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return $rgbString;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    static function renderNoData()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        return "<i>" . _EW_NO_DATA . "</i><br/><br/>";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }


    static function get_include_contents($filename, $param) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        if (is_file($filename)) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            ob_start();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            extract($param);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            require_once $filename;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            return ob_get_clean();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        return false;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    static function convertUrlQuery($query) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $query = str_replace("?","", $query);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $queryParts = explode('&', $query);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

        $params = array();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        foreach ($queryParts as $param) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $item = explode('=', $param);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            @$params[$item[0]] = @$item[1];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }

        return $params;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }


function renderHTMLCodeSnippet($projectId) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

    if (_EW_CLOUD_MODE) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output = "";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("<script type=\"text/javascript\">\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("<!--\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("var extrawatch_projectId='".$projectId."';\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("document.write(\"");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("<script src='"._EW_SCRIPT_HOST._EW_SCRIPT_HOST_DIR."agent.js.php\"+\n\"?projectId=\"+extrawatch_projectId+\"&env=ExtraWatchNoCMSEnv' type='text/javascript'><\/script>\");\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("-->\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("</script>\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    } else {
        $liveSite = $this->config->getLiveSiteWithSuffix();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		$output = "";
		$title = "Visitor counter, Heat Map, Conversion tracking, Search Rank";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		if (!$this->config->isAdFree()) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
			$output .= "<a href='http://www.extrawatch.com'><img src='".$liveSite."components/com_extrawatch/img/icons/extrawatch-logo-16x16.gif' alt='$title' title='$title' border='0' target='_blank'/></a>";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		}
        $output .= ("<script type=\"text/javascript\">\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("<!--\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("document.write(\"");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("<script src='".$liveSite.$this->env->renderAjaxLink('js','agent.js'."&env=".get_class($this->env)."&rand=".rand())."' type='text/javascript'><\/script>\");\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("-->\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $output .= ("</script>\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

    }

return $output;
}	

function getFirstUsersProject($database, $userId) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $result = $database->resultQuery(sprintf("select id from global_extrawatch_project where `userId` = '%d' order by id asc limit 1", (int) $userId));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
	return $result;
}

    static function fixFilePermissions($filesArray) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        foreach($filesArray as $file) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            @chmod(JPATH_SITE.DIRECTORY_SEPARATOR."components".DIRECTORY_SEPARATOR."com_extrawatch".DIRECTORY_SEPARATOR.$file, 0755);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
    }

    static function sureRemoveDir($dir, $DeleteMe)  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    {
        if (!$dh = @opendir($dir)) return;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        while (FALSE !== ($obj = readdir($dh))) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            if ($obj == '.' || $obj == '..') continue;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            if (!@unlink($dir . '/' . $obj)) extrawatch_sureRemoveDir($dir . '/' . $obj, TRUE);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        if ($DeleteMe) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            closedir($dh);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            @rmdir($dir);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
    }


function getUserId($database, $user, $password) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
	$query = sprintf("select id from global_extrawatch_user where `email` = '%s' and `password` = '%s' ", $user, $password);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $result = $database->resultQuery($query);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
	return $result;
}


function getProjectNameByProjectId($database, $projectId) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $result = $database->resultQuery(sprintf("select url from global_extrawatch_project where `id` = '%d' order by id asc limit 1", (int) $projectId));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
	return $result;
}

static function getTimezoneOffsetByTimezoneName($userTimezoneName){  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    try {
        $dtz = new DateTimeZone($userTimezoneName);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $time = new DateTime('now', $dtz);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $userTimezone = $time->format('Z') / 3600; // timezone difference in seconds / 3600  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        //ExtraWatchLog::debug("<br/>user timezone was not numeric, translated to: " . $userTimezone);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    } catch (Exception $e) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        echo("<!-- exception " . $e->getMessage() . " -->");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }
    return $userTimezone;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
}

    function secondsToHumanFormat($d) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $periods = array( 'd'    => 86400,  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            'h'   => 3600,  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            'm' => 60  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        );
        $parts = array();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        foreach ( $periods as $name => $dur )  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        {
            $div = floor( $d / $dur );  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            if ( $div == 0 )  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                continue;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            else if ( $div == 1 )  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $parts[] = $div . "" . $name;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            else
                $parts[] = $div . "" . $name . "";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $d %= $dur;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        $last = array_pop( $parts );  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        if ( empty( $parts ) )  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            return $last;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        else
            return join( ' ', $parts ) . "  " . $last;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    static function htmlspecialchars($value) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return htmlspecialchars(trim($value), ENT_QUOTES, "UTF-8");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    static function isValidIPv4($ip) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return preg_match('/\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/', $ip) !== 0;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    static public function rgbColorFromRatio($ratio) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $color = "";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $hue = ExtraWatchHelper::hueFromRatio($ratio);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $rgb = ExtraWatchHelper::HSV_TO_RGB($hue, 1, 1);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        if ($rgb) {
            $color = sprintf("#%02x%02x%02x", $rgb['R'], $rgb['G'], $rgb['B']);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            return $color;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        return $color;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }


	static function getUrlQueryParams() {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		$url = ExtraWatchHelper::getProtocol()."://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		$query_str = parse_url($url, PHP_URL_QUERY);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		parse_str($query_str, $query_params);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		return $query_params;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
	}

	static function updateLastLoginTime($database, $projectId) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $database->executeQuery(sprintf("update global_extrawatch_project set timeOfLastLogin = '%d' where `id` = '%d'", (int) time(), (int) $projectId));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
	}

    static function startsWith($haystack, $needle) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return $needle === "" || strpos($haystack, $needle) === 0;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    static function endsWith($haystack, $needle) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return $needle === "" || substr($haystack, -strlen($needle)) === $needle;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    static function checkIfRequestPathAllowed($extraWatch, $env, $task) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		if ($extraWatch->config->getLiveSite() != $env->getRootSite()) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
			$extraWatch->config->setLiveSite($env->getRootSite());  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
			ExtraWatchCache::clearCache($extraWatch->database);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		} else
		if ($task != "js" && $task != "ajax") {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            if ($extraWatch->config->getLiveSite() && !ExtraWatchHelper::startsWith(@$_SERVER['REQUEST_URI'], $extraWatch->config->getLiveSite().$env->getAdminDir())) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                die("Restricted access");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            }
        }
    }

    static function checkIfFileExistsInDir($path, $file) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $listOfFiles = scandir($path);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $result = in_array($file, $listOfFiles);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        if (!$result || $file == "." || $file == "..") {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            die("Restricted access");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
    }


    /**
     * Returns url like: http://www.thisweburl.com/directory  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     * @return string  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
     */
    static function getAbsoluteWebURL() {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $hostname = ExtraWatchHelper::getProtocol()."://" . $_SERVER['HTTP_HOST'];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $scriptName = $_SERVER['SCRIPT_NAME'];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $subdir = str_replace("/index.php", "", $scriptName);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

        $env = ExtraWatchEnvFactory::getEnvironment();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $adminDirName = $env->getAdminDir();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $subdir = str_replace("/".$adminDirName, "", $subdir);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

        return $hostname . $subdir;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

	static function getProtocol() {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		if( isset($_SERVER['HTTPS'] )  && $_SERVER['HTTPS'] != 'off' ) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
			return 'https';
		} else {
			return 'http';
		}
	}

}


