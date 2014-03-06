<?php

/**
 * @file
 * ExtraWatch - A real-time ajax monitor and live stats  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @package ExtraWatch  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @version 2.2  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @revision 1597  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @license http://www.gnu.org/licenses/gpl-3.0.txt     GNU General Public License v3  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @copyright (C) 2014 by CodeGravity.com - All rights reserved!  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @website http://www.codegravity.com  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 */
defined('_JEXEC') or die('Restricted access');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

if (!defined('DS')) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
	define('DS',DIRECTORY_SEPARATOR);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
}

if (_EW_CLOUD_MODE) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $projectId = @$_REQUEST['projectId'];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
	define('ENV',1);
}

$title = "Free live stats and visitor counter for Joomla, Wordpress, Drupal, Magento and Prestashop";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

require_once JPATH_BASE . DS . "components" . DS . "com_extrawatch" . DS . "includes.php";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


$extraWatch = new ExtraWatchMain();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
$extraWatchHTML = new ExtraWatchHTML();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
$referringURLParsed = parse_url(@$_SERVER['HTTP_REFERER']);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
$referringQuery = @$referringURLParsed['query'];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
$env = $_REQUEST['env'];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

?>
/** Credits: http://www.webtoolkit.info/javascript-url-decode-encode.html **/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
var ew_Utf8Encoder = { //added ex_ to avoid conflicts  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// URL utf-8 encoding  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
encode : function (str) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    return escape(this._utf8_encode(str));  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
},

// UTF-8 encoding
_utf8_encode : function (str) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
str = str.replace(/\r\n/g,"\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
var encoded_str = "";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

for (var n = 0; n < str.length; n++) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    var c = str.charCodeAt(n);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    if (c < 128) {
        encoded_str += String.fromCharCode(c);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }
    else if((c > 127) && (c < 2048)) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        encoded_str += String.fromCharCode((c >> 6) | 192);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        encoded_str += String.fromCharCode((c & 63) | 128);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    } else {
        encoded_str += String.fromCharCode((c >> 12) | 224);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        encoded_str += String.fromCharCode(((c >> 6) & 63) | 128);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        encoded_str += String.fromCharCode((c & 63) | 128);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
		}
	}
return encoded_str;
}

}
<?php

if (_EW_CLOUD_MODE) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output = ("var extrawatch_projectId='".$projectId."';\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= ("document.write(\"");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= ("<img src='"._EW_SCRIPT_HOST._EW_SCRIPT_HOST_DIR."extrawatch/".$extraWatch->env->renderAjaxLink('ajax','img')."&rand=" . (rand() % 100000) . "&amp;env=$env&amp;ref=\"+encodeURIComponent(document.referrer)+\"&amp;title=\"+ew_Utf8Encoder.encode((document.title)+\"&amp;uri=\"+encodeURIComponent(window.location.pathname)+\"&amp;params=\"+encodeURIComponent(location.search)+\"&amp;projectId=\"+extrawatch_projectId+\"' border='0' alt='$title' title='$title' style='width:0px;height:0px'/>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= ("\");\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= ("document.write(\"");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $uri = @$_SERVER['HTTP_REFERER'];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= $extraWatchHTML->renderHeatMapJS($uri, $referringQuery);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= ("\");\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
} else {
    $liveSite = $extraWatch->config->getLiveSiteWithSuffix();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output = ("document.write(\"");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= ("<img src='".$liveSite.$extraWatch->env->renderAjaxLink('ajax','img')."&rand=" . (rand() % 100000) . "&amp;env=$env&amp;ref=\"+encodeURIComponent(document.referrer)+\"&amp;title=\"+ew_Utf8Encoder.encode(document.title)+\"&amp;uri=\"+encodeURIComponent(window.location.pathname)+\"&amp;params=\"+encodeURIComponent(location.search)+\"' border='0' style='width:0px;height:0px'/>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= ("\");\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= ("document.write(\"");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $uri = @$_SERVER['HTTP_REFERER'];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= $extraWatchHTML->renderHeatMapJS($uri, $referringQuery);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $output .= ("\");\n");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

}
echo $output;
?>

function extrawatch_createRequestObject() {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    var ro;
    if(window.ActiveXObject){  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        ro = new ActiveXObject("Microsoft.XMLHTTP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }else{
        ro = new XMLHttpRequest();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }
    return ro;
}

function extrawatch_sendUnloadReq() {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
var rand='<?php echo $extraWatch->config->getRand(); ?>';  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    try {
        http = extrawatch_createRequestObject();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        var newdate = new Date();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        var url = "<?php echo($extraWatch->config->getLiveSiteWithSuffix()); ?><?php echo $extraWatch->env->renderAjaxLink('ajax','unloaded');?>&rand=" + rand + "&timeID="+newdate.getTime() + "&env=<?php echo($env); ?>&projectId=<?php echo(_EW_PROJECT_ID);?>";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        http.open("GET", url, true);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        http.send(null);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }
    catch (err) {
    }
}

window.addEventListener("unload", function(){  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    extrawatch_sendUnloadReq();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
}, true);


