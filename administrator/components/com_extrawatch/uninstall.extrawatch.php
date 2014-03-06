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

/** ensure this file is being included by a parent file */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
defined('_JEXEC') or die('Restricted access');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

function com_uninstall()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
{
    uninstallExtraWatchMain();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

  // remove extrawatch.zip from upload folder  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

  echo "ExtraWatch component successfully uninstalled.";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
}

function uninstallExtraWatchMain()  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
{

    global $database, $mainframe;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

    if (@ !defined('JPATH_BASE')) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        define('_JEXEC', 1);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $dirname = dirname(__FILE__);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $dirnameExploded = explode(DIRECTORY_SEPARATOR, $dirname);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $jBasePath = "";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $omitLast = 3;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        for ($i = 0; $i < sizeof($dirnameExploded) - $omitLast; $i++) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            $jBasePath .= $dirnameExploded[$i];  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            if ($i < (sizeof($dirnameExploded) - ($omitLast + 1)))  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                $jBasePath .= DIRECTORY_SEPARATOR;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
        define('JPATH_BASE', $jBasePath);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }

    if (!defined('DS')) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        define('DS', DIRECTORY_SEPARATOR);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    }



    if (!defined('JPATH_ROOT'))  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        require_once JPATH_BASE2 . DS . 'includes' . DS . 'defines.php';  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    if (!defined('JDEBUG'))  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        require_once JPATH_BASE2 . DS . 'includes' . DS . 'framework.php';  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

    $mainframe = & JFactory :: getApplication('site');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $mainframe->initialise();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    $database = & JFactory :: getDBO();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


    try {
        $database->setQuery("SELECT `value` as keepData from #__extrawatch_config where `name` = 'EXTRAWATCH_UNINSTALL_KEEP_DATA' limit 1 ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        $keepData = @$database->loadResult();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    } catch (Exception $e) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        // suppress
    }

    if (strtolower(@$keepData) == 'on') {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        echo("<b>Not deleting ExtraWatch database tables, because you set KEEP_DATA in Settings to true. <br/>Do not forget to delete these tables later, or install new version of ExtraWatch</b> <br/><br/>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        return array($mainframe, $database);  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    } else {

        try {

         $rootDir = dirname(__FILE__).DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."components".DIRECTORY_SEPARATOR."com_extrawatch";  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
         require_once($rootDir.DIRECTORY_SEPARATOR."includes.php");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

         $extraWatch = new ExtraWatchMain();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
         $extraWatch->downloads->deleteEverythingFromHtaccess();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
         $extraWatch->setup->dropTables();  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

		
        } catch (Exception $e) {  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
            // suppress  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        }
    }
}

?>
<iframe src="http://www.extrawatch.com/track/extrawatch/2.2/uninstall/?time=<?php echo time();?>" width="1px" height="1px" frameborder="0">  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
</iframe>

