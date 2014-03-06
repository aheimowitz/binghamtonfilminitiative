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

defined('_JEXEC') or die('Restricted access'); ?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

<a href='<?php echo $extraWatch->config->renderLink();?>'><img  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/map_icon.gif'/>&nbsp;<?php echo _EW_MENU_STATS;?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
</a>  &nbsp; 

<a href='<?php echo $extraWatch->config->renderLink('goals');?>'><img  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/goal.gif'/>&nbsp;<?php echo _EW_MENU_GOALS;?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
</a>  &nbsp; 
<a href='<?php echo $extraWatch->config->renderLink('graphs');?>'><img  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/trend_icon.gif'/>&nbsp;<?php echo _EW_ADMINHEADER_GRAPHS;?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
</a>  &nbsp; 
<a href='<?php echo $extraWatch->config->renderLink('history');?>'><img  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/history.png'/>&nbsp;<?php echo _EW_MENU_HISTORY;?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
</a>  &nbsp; 
<a href='<?php echo $extraWatch->config->renderLink('antiSpam');?>'><img  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/antispam.gif'/>&nbsp;<?php echo _EW_SETTINGS_ANTI_SPAM;?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
</a>  &nbsp; 
<a href='<?php echo $extraWatch->config->renderLink('emails');?>'><img  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/emails.png'/>&nbsp;<?php echo _EW_MENU_EMAILS;?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
</a>  &nbsp; 

<a href='<?php echo $extraWatch->config->renderLink('settings');?>'><img  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
    src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/settings.gif'/>&nbsp;<?php echo _EW_MENU_SETTINGS;?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
</a>

<?php if (_EW_CLOUD_MODE) { ?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
&nbsp;
<a href='?action=logout' style="color: red;"> &nbsp;Logout  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
</a>
<?php } else { ?>
<a href='<?php echo $extraWatch->config->renderLink('credits');?>'><img  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
        src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/credits.png'/>&nbsp;<?php echo _EW_MENU_CREDITS;?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
</a>
<?php } ?>

<?php if (!_EW_CLOUD_MODE) { ?>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
<img
        src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/heatmap-disabled.png' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_HEATMAP;?>' />&nbsp;<span class='ewDisabled' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_HEATMAP;?>'><?php echo _EW_ADMINHEADER_HEATMAP;?></span>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

<img
        src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/click-disabled.png' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_CLICK_AREAS;?>' />&nbsp;<span class='ewDisabled' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_CLICK_AREAS;?>'><?php echo _EW_ADMINHEADER_CLICK_AREAS;?></span>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

    <img
        src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/seo-disabled.png' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_SEO_REPORT;?>' />&nbsp;<span class='ewDisabled' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_SEO_REPORT;?>'>SEO</span>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

<img
        src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/users-disabled.png' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_USERS;?>'/>&nbsp;<span class='ewDisabled' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_USERS;?>'><?php echo _EW_MENU_USERS;?></span>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
<img
        src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/flow-disabled.png' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_FLOW;?>' />&nbsp;<span class='ewDisabled' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_FLOW;?>'><?php echo _EW_ADMINHEADER_FLOW;?></span>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 
<img
        src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/downloads-disabled.png' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_DOWNLOADS;?>' />&nbsp;<span class='ewDisabled' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_DOWNLOADS;?>'><?php echo _EW_MENU_DOWNLOADS;?></span>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

 
<img
        src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/status-disabled.png' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_STATUS;?>' />&nbsp;<span class='ewDisabled' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_STATUS;?>'><?php echo _EW_MENU_STATUS;?></span>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 
<img
        src='<?php echo($extraWatch->config->getLiveSiteWithSuffix());?>components/com_extrawatch/img/icons/sizes-disabled.png' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_COMPONENTS;?>' />&nbsp;<span class='ewDisabled' title='<?php echo _EW_MENU_AVAILABLE_IN_PRO_COMPONENTS;?>'><?php echo _EW_ADMINHEADER_COMPONENTS;?></span>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
<?php } ?>



<br/><br/>