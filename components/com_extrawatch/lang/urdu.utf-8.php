<?php

/**
 * @file
 * ExtraWatch - A real-time ajax monitor and live stats  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @package ExtraWatch  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @version @VERSION@  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @revision @REVISION@  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @license http://www.gnu.org/licenses/gpl-3.0.txt     GNU General Public License v3  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @copyright (C) @YEAR@ by CodeGravity.com - All rights reserved!  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @website http://www.codegravity.com  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 */

defined('_JEXEC') or die('Restricted access');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

//ExtraWatch language file - to create a new language file, just copy the english.php to eg. german.php and place into./components/com_extrawatch/lang/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Main Menu.
DEFINE('_EW_MENU_STATS', "لائیو اعدادوشمار");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_GOALS', "اہداف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_SETTINGS', "ترتیبات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_CREDITS', "کریڈٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_FAQ', "عمومی سوالات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_DOCUMENTATION', "دستاویز بندی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_LICENSE', "لائسنس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_DONATORS', "حامی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_SUPPORT', "جملہ واچ کی مدد کریں اور بیک اینڈ سے اپنے اشتہارات ختم کروائیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


// Left visitors real-time window.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_VISITORS', "تازہ ترین وزیٹرز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_BOTS', "بوٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_CAME_FROM', "جہاں سے آئے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_MODULE_NOT_PUBLISHED', "آپکا جملہ واچ موڈیول شائع نہیں ہوا۔نئے اعدادوشمار ریکارڈ نہیں کیے جا رہے۔ اس کو شائع کرنے کرنے کے لئے، موڈیولز سیکشن میں جائیں اور اس کو تمام صفحات پر شائع کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_PANE_LOADING', "وزٹس لوڈ ہو رہے ہیں۔۔۔");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Right stats window.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TITLE', "ہفتہ بھر کےوزٹ کے اعدادوشمار");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_WEEK', "ہفتہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_THIS_WEEK', "اس ہفتہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_UNIQUE', "منفرد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADS', "لوڈز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_HITS', "ہٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TODAY', "آج");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_FOR', "کے لیے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ALL_TIME', "تمام وقت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_EXPAND', "پھیلایئں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_COLLAPSE', "سمیٹیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_URI', "صفحات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_COUNTRY', "ممالک");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_USERS', "یوزرز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_REFERERS', "حوالہ دینے والے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP', "IPs");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_BROWSER', "براؤزرز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_OS', "OS");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYWORDS', "کی ورڈز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_GOALS', "اہداف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TOTAL', "مجموعہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_DAILY', "روزانہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_DAILY_TITLE', "روزانہ کے اعدادوشمار");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ALL_TIME_TITLE', "تمام وقت کے اعدادوشمار");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADING', "لوڈنگ۔۔۔");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADING_WAIT', "لوڈ ہو رہا ہے ۔۔۔۔۔انتطار فرمائیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_TITLE', " بلاکنگIP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_ENTER', "کا خود اندراج کریں IP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_MANUALLY', "ً آئی پی ایڈریس کا اندراج کریں جس کو آپ بلاک کرنا چاہتے ہیں مثلاً 45۰217۰242۰11 یا 217۰* ان تمام آئی پیز کو بلاک کرنے کے لیے جو وائلڈ کارڈ سے میچ کرتے ہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_TOGGLE', "کیا واقعی بلاکنگ کو ٹوگل کرنا ہے ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_PANE_LOADING', "اعدادوشمار لوڈ ہو رہے ہیں۔۔۔");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Settings.
DEFINE('_EW_SETTINGS_TITLE', "ترتیبات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_DEFAULT', "ڈیفالٹ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_SAVE', "محفوظ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_APPEARANCE', "ظاہریت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_FRONTEND', "فرنٹ اینڈ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_HISTORY_PERFORMANCE', "تاریخ اور کارکردگی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ADVANCED', "مزید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_IGNORE', "نظر انداز کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_BLOCKING', "بلاکنگ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_EXPERT', "ماہر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_CONFIRM', "کیا آپ واقعی تمام اعدادوشمار اور وزیٹرڈیٹا کو ری سیٹ کرنا چاہتے ہیں؟");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_ALL', "سب کو ری سیٹ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_ALL_LINK', "تمام اعدادوشمار اور وزیٹرڈیٹا کو ری سیٹ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_LANGUAGE', "زبان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_SAVED', "ترتیبات محفوظ ہو گئیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ADD_YOUR_IP', "شامل کریںIPاپنا");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_TO_THE_LIST', "فہرست میں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Other / mostly general.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TITLE', "جملہ مانیٹر AJAX ایک رئیل ٹائم");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BACK', "پیچھے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ACCESS_DENIED', "آپ کے پاس اس کو دیکھنے کی کوئی اجازت نہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LICENSE_AGREE', "میں اوپروالی شرائط و ضوابط سے متفق ہوں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LICENSE_CONTINUE', "جاری ہے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SUCCESS', "آپریشن کامیاب رہا");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_RESET_SUCCESS', "تمام اعدادوشمار اور وزیٹر ڈیٹا کامیابی سےختم ہو گیا ہے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_RESET_ERROR', "ڈیٹا کامیابی سے ختم نہیں ہوا،کچھ غلط ہو گیا ہے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CREDITS_TITLE', "کریڈٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRENDS_DAILY_WEEKLY', "روزانہ اور ہفتہ وار اعدادوشمار ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_1', " نے اجازت نہیں دی۔مہربانی کر کے یہ اعدادوشماراس ڈومین سے دیکھیں جو آپ نے جملہ کی کونفیگیوریشن۔پی ایچ پی  میں مخصوص کی ہے ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_2', "شائد آپ ڈومین کے نام سے پہلے ڈبلیو ڈبلیو  ڈبلیو لگانا بھول گئے ہیں۔ آپکا جاوا سکرپٹ ایکسس کرنے کی کوشش کر رہا ہے۔ ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_3', "کی جانب سے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_4', "کیا چیز اس کو ایک مختلف ڈومین بناتی ہے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Header.
DEFINE('_EW_HEADER_DOWNLOAD', "تازہ ترین ایکسٹین کا کوڈ حاصل کریں سے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEADER_CAST_YOUR', "براہ مہربانی اپنا کاسٹ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEADER_VOTE', "ووٹ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Tooltips.
DEFINE('_EW_TOOLTIP_CLICK', "ٹول ٹپ دیکھنے کے لئے کلک کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_MOUSE_OVER', "ٹول ٹپ دیکھنے کے لئے ماوس پوائنٹر کو اوپر رکھیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_YESTERDAY_INCREASE', "گزشتہ دن کا اضافہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_HELP', "آن لائن بیرونی مدد کھولتا ہےکے لئے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_WINDOW_CLOSE', "یہ ونڈو بند کر دیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_PRINT', "پرنٹ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Goals.
DEFINE('_EW_GOALS_INSERT', "ایک نیا ہدف داخل کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_UPDATE', "ایک گول نمبر کو اپ ڈیٹ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ACTION', "ایکشن");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE', "نیا ہدف کا ٹائٹل");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_NEW', "نیا ہدف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_RELOAD', "ری لوڈ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ADVANCED', "ایڈوانسڈ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_NAME', "نام");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ID', "id");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_URI_CONDITION', " کی شرطURI");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_URI_INVERSED', " کی الٹی شرطURI");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_GET_VAR', "GET var");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_GET_CONDITION', " کی شرطGET");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_VAR', "POST Var");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_CONDITION', "کی شرطPOST");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE_CONDITION', "عنوان کی شرط");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_USERNAME_CONDITION', "یوزر کے نام کی شرط");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_IP_CONDITION', " کی شرطIP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_IP_INVERSED', " کی الٹی شرطIP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_CAME_FROM_CONDITION', "جہاں سے آئے کی شرط");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_BLOCK', "بلاک");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_REDIRECT', "کی طرف ری ڈائریکٹ URL");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_HITS', "ہٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ENABLED', "Enabled");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_EDIT', "ایڈٹ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_DELETE', "ڈیلیٹ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_DELETE_CONFIRM', "آپ تمام حالیہ اعدادوشمار کھو دیں گے۔ کیا آپ واقعی ایک گول نمبر کو ڈیلیٹ کرنا چاہتے ہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Frontend.
DEFINE('_EW_FRONTEND_COUNTRIES', "ممالک");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS', "وزیٹرز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_TODAY', "آج");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_YESTERDAY', "کل");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_THIS_WEEK', "اس ہفتہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_LAST_WEEK', "گزشتہ ہفتہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_THIS_MONTH', "اس ماہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_LAST_MONTH', "گزشتہ ماہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_TOTAL', "مجموعہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Settings description - quite long.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_DEBUG', "جملہ واچ ڈی بگ موڈ میں ہے۔ اس طرح سے آپ غلطیوں کی وجہ تلاش کر سکتے ہیں۔ اس کو بند کرنے کے لئے اس کی ویلیو کو 1 سے 0 کر دیں EXTRAWATCH_DEBUG in /components/com_extrawatch/config.php");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_MAX_ROWS', "جب اعدادوشمار پھیلاو والے موڈ میں ہوں تو کتنی قطاریں دکھائی جائیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_IP_HITS', "تمام آئی پی ایڈریسز جن پر پچھلے دنوں میں اس ویلیو سے کم ہٹس ہوئی ہیں وہ آئی پی کی ہسٹری میں سے ختم ہو جایئن گے۔");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_URL_HITS', " تمام یو آر ایلز جن پر پچھلے دنوں میں اس ویلیو سے کم ہٹس ہوئی ہیں وہ آئی پی کی ہسٹری میں سے ختم ہو جایئن گے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_IP', "اعدادوشمار میں سے مخصوص آئی پی نکالیں۔ ایک نئی لائن سے علیحدہ کریں۔ آپ یہاں وائلڈ کارڈ بھی استعمال کر سکتے ہیں۔ <br />مثلاً .*192 نظر انداز کرے گا <br/>Eg. 192.* 192.168.51.31, 192.168.16.2, etc..");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UPDATE_TIME_VISITS', "وزیٹرز کا ریفریش ہونے کا وقت ملی سیکنڈز میں، ڈیفالٹ 2000 ہے،اس سے محتاط رہیں۔ پھر جملہ واچ بیک اینڈ کو دوبارہ لوڈ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UPDATE_TIME_STATS', "اعدادوشمار کا ریفریش ہونے کا وقت ملی سیکنڈز میں، ڈیفالٹ 4000 ہے،اس سے محتاط رہیں۔ پھر جملہ واچ بیک اینڈ کو دوبارہ لوڈ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_MAXID_BOTS', " ایک ڈیٹابیس میں کتنےبوٹ وزیٹس رکھے جائیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_MAXID_VISITORS', "ایک ڈیٹابیس میں کتنےحقیقی  وزیٹس رکھے جائیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LIMIT_BOTS', "بیک اینڈ میں آپ کتنے بوٹس دیکھیں گے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LIMIT_VISITORS', "بیک اینڈ میں آپ کتنے حقیقی وزیٹرز دیکھیں گے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_VISITS', "زیادہ سے زیادہ حروف جو کہ لمبے عنوانات اور یو۔آر۔آئیز میں دکھانے ہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_STATS', " زیادہ سے زیادہ حروف جو کہ دائیں اعدادوشمارکے پینل میں دکھانے ہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_KEEP_DAYS', "ڈیٹا بیس میں اعدادوشمار کتنے دن رکھےجائیں، 0 = لا محدود");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TIMEZONE_OFFSET', "جب آپ اپنے ہوسٹنگ سرور سے ایک مختلف ٹائم زون میں ہوں۔ مثبت یا منفی قدر گھنٹوں میں)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_WEEK_OFFSET', "ہفتہ کا آف سیٹ، ٹائم سٹیمپ 3600 * 24 * 7 ہفتہ کا نمبر دیتی ہے1970۔1۔1 سے۔ یہ آف سیٹ ایک تصیح ہے اس کو سوموار سے شروع کرنے کے لئے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_DAY_OFFSET', " دن کا آف سیٹ، ٹائم سٹیمپ 3600 * 24 دن کا نمبر دیتی ہے1970۔1۔1 سے۔ یہ آف سیٹ ایک تصیح ہے اس کو 00:00 پر شروع کرنے کے لئے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_HIDE_LOGO', "<b>( ورژن میں کار آمدPRO)</b> ایک خالی آئیکون 1بائی 1 کو فرنٹ اینڈ میں استعمال کرنے کے لیے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IP_STATS', "آئی پی ایڈریس کے اعدادوشمار کو کریں۔ بعض ممالک میں، آئی پی کو لمبے عرصے تک ڈیٹا بیس میں رکھنا قانوناً منع ہے۔ اپنی ذمہ داری پر استعمال کریں ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HIDE_ADS', "یہ ترتیب اشتہارات کو بیک اینڈ سے چھپاتی ہے، اگر یہ واقعی آپ کو تنگ کرتے ہیں تو۔ ان کو رکھتے ہوئے آپ اس ٹول کی مزید ترقی میں معاون ہوں گے۔ آپ کا شکریہ ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_ONCLICK', " ان چیک کریں، اگر آپ ماوس کلک کی بجائے ماوس اوور پر ٹول ٹپ دکھانا چاہتے ہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SERVER_URI_KEY', " 'SCRIPT_URL'ڈیفالٹ ہے،   جو کہ معیار ہے اگر آپ یو آر ایل کو دوبارہ لکھ رہے ہیں تو، اگر یہ صرف انڈیکس کو لاگ کر رہا ہے تو اس کو ایسے بھی سیٹ کیا جا سکتا ہے 'REDIRECT_URL'");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_BLOCKING_MESSAGE', "پیغام جو بلاکڈ یوزر کو دکھائی دے گا یا مزید معلومات کہ آپ ان یوزرز کو کیوں بلاک کر رہے ہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_WIDTH', "ٹول ٹپ کی چوڑائی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_HEIGHT', "ٹول ٹپ کی لمبائی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_URL', "آپ یہاں کوئی بھی یو آر ایل لکھ سکتے ہیں، وزیٹر کا آئی پی دیکھنے کے لیے۔ {آئی پی} وزیٹر کے آئی پی سے بدل دیا جاےَ گا. Eg. http://somewebsite.com/query?iplookup={ip}");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_URI', "آپ یہاں کوئی بھی یو آر آئی جس کو آپ اعدادوشمار سے نظر انداز کرنا چاہتے ہیں، لکھ سکتے ہیں۔ آپ یہاں وائلڈ کارڈ * یا ؟ بھی استعمال کر سکتے ہیں۔ . Eg.: /freel?n* ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_NAME', "یہاں ایک ہدف کا نام مخصوص کریں۔ یہ نام آپ اعدادوشمار میں دیکھیں گے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_URI_CONDITION', "ہر وہ چیز جو آپکی ڈومین نیم کے بعد ہوتی ہے جیسے http://www.codegravity.com/projects/ the URI is: /projects/ (Example to use: <b>/projects*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_GET_VAR', " ایک ایسا ویریبل جس کو آپ عام طور پریو آرایل میں دیکھ سکتے ہیں ؟ کے بعد جیسےGET. Eg. http://www.codegravity.com/index.php?<u>name</u>=peter&amp;<u>surname</u>=smith. آپ ساری ویلیو کھوجنے کے لیے* بھی استعمال کر سکتے ہیں. (Example to use: <b>n*me</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_GET_CONDITION', "یہاں آپ کو گزشتہ فیلڈ سے ایک ویلیو کا جوڑ مخصوص کرنا ہو گا۔ مثلاً: <b>p?t*r</b>) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_POST_VAR', "بلکل ایسے ہی مگر ہم وہ ویلیوز چیک کر رہے ہیں جو فارمز سے جمع ہوئی ہیں۔ چناچہ جب آپ اپنی ویب سائٹ پر فارم بنائیں گے، جس میں ایک فیلڈ ہو گی &lt;input type='text' name='<u>experiences</u>' /&gt;. (Example to use: <b>exper*ces</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_POST_CONDITION', "فیلڈ کی اس ویلیو کے لیے ایک میچ مثلاً ہم یہ جاننا چاہتے ہیں کہ یوزر کو جاوا کا تجربہ ہےPOST (مثلاً: <b>*java*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_TITLE_CONDITION', "ایک صفحہ کا عنوان جس کو میچ کرنا ہے۔ (مثلاً: <b>*freelance programmers*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_USERNAME_CONDITION', "ایک لاگڈ ان یوزر کا ایک نام مثلاً (<b>psmith*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_IP_CONDITION', "آئی پی جہاں سے یوزر آیا ہے: مثلاً (<b>201.9?.*.*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_CAME_FROM_CONDITION', " جہاں سے یوزر آیا ہے: مثلاً ایک یو آر ایل (<b>*www.google.*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_REDIRECT', "یوزر آپکی مخصوص کردہ یو۔آر۔آئی پر ری ڈائریکٹ ہو گیا ہے۔ اس کی اہمیت 'بلاکنگ' سے زیادہ ہے۔ مثلاً  ( <b>http://www.codegravity.com/goaway.html</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_GOALS', "کتنے حروف گولز ٹیبل میں سے کم کرنے ہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_NO_BACKLINK', "کوڈ  گریوٹی ڈاٹ کام کا بیک لنک، آپ اس کوبند کر سکتے ہیں، لیکن ہم آپ کے مشکور ہوں گے اگر آپ اس کو رہنے دیں گے۔ آپکا شکریہ <b>(functional in PRO version)</b>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES', "فرنٹ اینڈ موڈیول میں ممالک کے کل اعدادوشمار دکھائیں۔ اگر تبدیلی کی گئی، یہ سیٹنگ یا ترتیب مقررہ وقت کے بعد فرنٹ اینڈ میں موثر ہو گیCACHE_FRONTEND_ ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_FIRST', "اگر آپ ویزٹرز/ممالک کی ترتیب آپس میں بدلنا چاہتے ہیں تو اس کو ان چیک کر دیں اور وزیٹرز پہلے ظاہر ہوں گے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_NUM', "ممالک کی تعداد جو کہ فرنٹ اینڈ میں ظاہر کرنے ہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS', "فرنٹ اینڈ موڈیول میں وزیٹرز کے کل اعدادوشمار دکھائیں۔ اگر تبدیلی کی گئی، یہ سیٹنگ یا ترتیب مقررہ وقت کے بعد فرنٹ اینڈ میں موثر ہو گیCACHE_FRONTEND_");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_COUNTRIES', "فرنٹ اینڈ میں ممالک کا مجموعہ حاصل کرنے میں کیشے کا وقت سیکنڈز میں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_VISITORS', " فرنٹ اینڈ میں وزیٹرز کا مجموعہ حاصل کرنے میں کیشے کا وقت سیکنڈز میں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TODAY', "فرنٹ اینڈ  میں وزیٹرز دکھانے کے لئے: آج کے لیے۔ اگر تبدیلی کی گئی، یہ سیٹنگ یا ترتیب مقررہ وقت کے بعد فرنٹ اینڈ میں موثر ہو گیCACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_YESTERDAY', "فرنٹ اینڈ  میں وزیٹرز دکھانے کے لئے: کل کے لیے۔ اگر تبدیلی کی گئی، یہ سیٹنگ یا ترتیب مقررہ وقت کے بعد فرنٹ اینڈ میں موثر ہو گی CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_THIS_WEEK', " فرنٹ اینڈ  میں وزیٹرز دکھانے کے لئے: اس ہفتہ کے لیے۔ اگر تبدیلی کی گئی، یہ سیٹنگ یا ترتیب مقررہ وقت کے بعد فرنٹ اینڈ میں موثر ہو گی CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_LAST_WEEK', " فرنٹ اینڈ  میں وزیٹرز دکھانے کے لئے: گزشتہ ہفتے کے لیے۔ اگر تبدیلی کی گئی، یہ سیٹنگ یا ترتیب مقررہ وقت کے بعد فرنٹ اینڈ میں موثر ہو گی CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_THIS_MONTH', " فرنٹ اینڈ  میں وزیٹرز دکھانے کے لئے: اس ماہ کے لیے۔ اگر تبدیلی کی گئی، یہ سیٹنگ یا ترتیب مقررہ وقت کے بعد فرنٹ اینڈ میں موثر ہو گی  CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_LAST_MONTH', " فرنٹ اینڈ  میں وزیٹرز دکھانے کے لئے:گزشتہ ماہ کے لیے۔ اگر تبدیلی کی گئی، یہ سیٹنگ یا ترتیب مقررہ وقت کے بعد فرنٹ اینڈ میں موثر ہو گی CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TOTAL', " کل وزیٹرز دکھانے کے لئےجب سے جملہ واچ انسٹال کی گئی ہے۔ اگر تبدیلی کی گئی، یہ سیٹنگ یا ترتیب مقررہ وقت کے بعد فرنٹ اینڈ میں موثر ہو گی CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LANGUAGE', "زبان کی فائل استعمال کرنے کے لیے۔ اگر آپ ایک نئی زبان کی فائل بنانا چاہتے ہیں تو پہلے پروجیکٹ کا ہوم پیج دیکھیں اور اگر زبان کی فائل ابھی بھی یہاں نہیں ہے تو بس انگلش ڈاٹ پی ایچ پی اس ڈائریکٹری میں کاپی کر دیں۔ پھردائیں طرف تمام اہم ویلیوز کا ترجمہ کریں۔ /components/com_extrawatch/lang/");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS', "گولز آپ کو سپیشل پیرامیٹرز مخصوص کرنے کے قابل بناتے ہیں۔ جب یہ پیرامیٹر میچ کرتے ہیں تو گول کاونٹر بڑھ جاتا ہے۔ اس طرح سے آپ نگرانی کر سکتے ہیں کہ یوزر نے ایک مخصوص لنک کو وزٹ کیا ہے، ایک خاص ویلیو کو پوسٹ کیا ہے، ایک خاص یوزر کا نام ہے یا ایک خاص ایڈریس سے آیا ہے۔ آپ ایسے یوزر کو بلاک یا کسی دوسرے لنک پر بھیج سکتےہیں۔");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_INSERT', "نام کی فیلڈ کے علاوہ تمام میں آپ * یا ؟ وائلڈ کارڈ کے طور پر استعمال کر سکتے ہیں: مثلاً: ?ear (will match: near, tear, ..),  p*r (will match: pr, peer, pear ..) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_BLOCK', "1 پر سیٹ کریں اگر آپ وزیٹر کو بلاک کرنا چاہتے ہیں۔ وہ باقی مواد نہیں دیکھ سکے گا، صرف یہ پیغام کہ وہ بلاک ہو گیا ہے۔ بغیر کسی ری ڈائریکش کے اور اسکا آئی پی 'بلاکڈ' اعدادوشمار میں شامل ہو گیا ہے (Example to use: <b>1</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* new translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY_CONDITION', "ملک کے لیے شرط");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY_INVERSED', "ملک کے لیے  الٹی شرط");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_COUNTRY_CONDITION', " 2 حروف کا ملک کا کوڈ بڑے حروف میں(Eg: <b>TH</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_INTERNAL', "اندرونی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_FROM', "سے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TO', "کو");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ADD_TO_GOALS', " گولز میں درج کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_ADD_GOAL_COUNTRY', "اس ملک کے لیے گول کا اضافہ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_REPORT_BUG', "بگ یا فیچر کو رپورٹ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY', "ملک");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


/* translations 1.2.8b_12 */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_UPPERCASE', "اگر آپ چاہتے ہیں کہ ممالک کے نام بڑے حروف میں ہوں فرنٹ اینڈ میں (Eg: GERMANY, UNITED KINGDOM کی بجائے Germany, United Kingdom)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_USERS', " فرنٹ اینڈ میں یوزرز حاصل کرنے میں کیشے کا وقت سیکنڈز میں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TOTAL_INITIAL', "ابتدائی ویلیو جو مجموعے میں نظر آئے: فرنٹ اینڈ میں۔ کارآمد ہے اگر آپ کسی دوسرے ٹول سے آئے ہیں تو مثلاً 2000۔ واپس 0 پر سیٹ کر دیں اگر آپ یہ فیچر استعمال کرنا نہیں چاہتے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_USER', "اس ٹیکسٹ باکس میں درج یوزرز کو نظر انداز کریں۔ ایک ہر لائن میں۔(Eg.: myself {line break} mark_*) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_USERS_MOST', " آج کا سب سے زیادہ متحرک یوزر، مجموعے میں سے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SPAMWORD_BANS_ENABLED', "نیچے سپیم ورڈ کی لسٹ میں سےالفاظ پر مشتمل بینزکو قابل بنایئں؟");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SPAMWORD_LIST', "عام سپیم الفاظ جو سپیم بوٹس استعمال کرتے ہیں۔ آپ یہاں وائلڈ کارڈ استعمال کر سکتے ہیں۔ اگر درج بالا سیٹنگ قابل عمل ہوئی، جملہ واچ یہ چیک کرے گا کہ کیا حملہ آور نےآپکی ویب سائٹ پر ان سپیم الفاظ پر مشتمل ایک فارم جمع کروایا ہے۔ کام کرتا ہے اگر فارم صرف جملہ والی ویب سائٹ لوڈ کرے- فورم، آراء، لیکن یہ بلاک کرنے کے لیے مکمل موثر ان سپیم بوٹس کے خلاف ہے جو ہر ممکن فارم جمع کروانے کی کوشش کرتے ہیں۔)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ANTI_SPAM', "اینٹی-سپیم");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_USER_LINK', "ایک لنک فرنٹ اینڈ یوزرز کے موڈیول میں- آپ کو ایک یو آر ایل مخصوص کرنے کے قابل بناتا ہے، جو تب کھلے گی جب یوزر یوزرنیم پر کلک کرے گا۔ لازماً {یوزر} کی سٹرنگ پر مشتمل ہو، جو اصل یوزر سے بدل جائے گا۔ (Eg. index.php?option=com_comprofiler&task=userProfile&user={user}) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* translations 1.2.11b */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYPHRASE', "کی فریزز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HISTORY_MAX_VALUES', "زیادہ سے زیادہ ویلیو، ہسٹری کے ٹیب میں (Example: <i>100</i>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_DESC_ONLY_LAST_URI', "وزٹس میں صرف آخری وزٹ کیا گیا صفحہ دکھائیں، سارے نہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HIDE_REPETITIVE_TITLE', "وزٹس میں وزٹ کیے گئے صفحہ کے عنوان سے سائٹ کا مکرر نام چھپائیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HISTORY_MAX_DB_RECORDS', "وزٹ ہسٹری کے لیے زیادہ سے زیادہ وزیٹرز کی تعداد جو ڈیٹا بیس میں رکھنی ہے۔ اس ترتیب سے محتاط رہیں، اگر آپ کے پاس ٹریفک زیادہ ہے تو یہ بہت تیزی سے بڑھ سکتا ہے۔ ہمیشہ چیک کریں کہ ہسٹری ٹیبل سٹیٹس میں کتنا ڈیٹا رکھتا ہے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UNINSTALL_KEEP_DATA', "ان انسٹال کرنے پر ڈیٹا بیس ٹیبل رہنے دیں۔  اس آپشن کو ان انسٹال کرنے سے پہلے چیک لگا دیں اگر آپ ایک اپ گریڈ کر رہے ہیں اور ڈیٹا رکھنا چاہتے ہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* email reports */
DEFINE('_EW_DESC_EMAIL_REPORTS_ENABLED', " آپ گزشتہ دن کی رپورٹس کے ساتھ شب کی ای میلز موصول کریں گے جو آپ صبح کو پڑھ سکتے ہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_REPORTS_ADDRESS', "ای میلز ایڈریس جس پر آپ یہ رپورٹس موصول کریں گے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_PERCENT_HIGHER_THAN', "ای میل رپورٹس میں صرف وہ قطاریں شامل کریں جہاں فیصد {ویلیو} سے زیادہ ہے۔ اس کو 0 پر سیٹ کر دیں اگر آپ اس فیچر کو استعمال نہیں کرنا چاہتے۔ مثلاً <i>(5)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_ONE_DAY_CHANGE_POSITIVE', "ای میل رپورٹس میں صرف ایک مثبت دن کی تبدیل شدہ ویلیوز شامل کریں جو{ویلیو}  فیصد سے زیادہ ہیں۔ اس کو 0 پر سیٹ کر دیں اگر آپ اس فیچر کو استعمال نہیں کرنا چاہتے۔ مثلاً <i>(example: 5)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_ONE_DAY_CHANGE_NEGATIVE', " ای میل رپورٹس میں صرف ایک منفی دن کی تبدیل شدہ ویلیوز شامل کریں جو{ویلیو}  فیصد سے کم ہیں۔ اس کو 0 پر سیٹ کر دیں اگر آپ اس فیچر کو استعمال نہیں کرنا چاہتے۔ مثلاً <i>(example: -10)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEVEN_DAY_CHANGE_POSITIVE', " ای میل رپورٹس میں صرف سات مثبت دن کی تبدیل شدہ ویلیوز شامل کریں جو{ویلیو}  فیصد سے زیادہ ہیں۔ اس کو 0 پر سیٹ کر دیں اگر آپ اس فیچر کو استعمال نہیں کرنا چاہتے۔ مثلاً<i>(example: 2)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEVEN_DAY_CHANGE_NEGATIVE', " ای میل رپورٹس میں صرف سات منفی دن کی تبدیل شدہ ویلیوز شامل کریں جو{ویلیو}  فیصد سے کم ہیں۔ اس کو 0 پر سیٹ کر دیں اگر آپ اس فیچر کو استعمال نہیں کرنا چاہتے۔ مثلاً <i>(example: -13)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_TWENTY_EIGHT_DAY_CHANGE_POSITIVE', " ای میل رپورٹس میں صرف اٹھائیس مثبت دن کی تبدیل شدہ ویلیوز شامل کریں جو{ویلیو}  فیصد سے زیادہ ہیں۔ اس کو 0 پر سیٹ کر دیں اگر آپ اس فیچر کو استعمال نہیں کرنا چاہتے۔ مثلاً <i>(example: 2)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_TWENTY_EIGHT_DAY_CHANGE_NEGATIVE', " ای میل رپورٹس میں صرف اٹھائیس منفی دن کی تبدیل شدہ ویلیوز شامل کریں جو{ویلیو}  فیصد سے کم ہیں۔ اس کو 0 پر سیٹ کر دیں اگر آپ اس فیچر کو استعمال نہیں کرنا چاہتے۔ مثلاً <i>(example: -13)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_DESC_FRONTEND_NOFOLLOW', "<b>(ورژن میں کارآمد PRO)</b>آپ لوگوکا لنک فراہم کردہ وصف کے ساتھ بنانا چاہتے ہیں اس ترتیب کو فعال کریں اگر rel='nofollow' ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_NAME_TRUNCATE', " ای میل کی قطارکے نام کے زیادہ سے زیادہ حروف۔ اس کو تبدیل کرلیں اگر آپکے ای میل کلائنٹ کی ونڈو بہت چھوٹی ہے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_MENU_HISTORY', "تاریخ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_EMAILS', "ای میلز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_STATUS', "ڈیٹا بیس کا سٹیٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_BLOCKED', "یہ آئی پیز اینٹی-سپیم کی طرف سے بلاک تھے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_HISTORY_VISITORS', "ویزیٹرز کی ہسٹری");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_SHOWING_ONLY', "صرف آخری ریکارڈز دکھا رہا ہے۔ اس ویلیو کو تبدیل کرنے کے لیے ترتیبات اور پھر ہسٹری اور پرفارمنس میں HISTORY_MAX_DB_RECORDS ۔ محتاط رہیں، یہ ترتیب ذیلی ڈیٹا کے لوڈ ہونے کے دورانئے پر اثر انداز ہو سکتی ہے   ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_BUG', "بگ کو رپورٹ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_FEATURE', "فیچر کی درخواست کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_VISITS_CAME_FROM_KEYWORDS', "کی ورڈز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_BLOCKING_UNBLOCK', "ان بلاک");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYPHRASE ', "کی فریز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATUS_DATABASE_TABLE_NAME', "ٹیبل کا نام");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_ROWS', "قطاریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_DATA', "ڈیٹا");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_TOTAL', "مجموعہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_EMAIL_REPORTS', "ای میل رپورٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORT_GENERATED', "کل سے فلٹر شدہ ای میل رپورٹ بنائی گئی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_VALUE_FILTERS', "ای میل کی ویلیو کے فلٹرز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_VALUE', "ویلیو");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_PERCENT', "فیصد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_1DAY_CHANGE', "1 دن کی تبدیلی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_7DAY_CHANGE', " 7 دن کی تبدیلی ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_28DAY_CHANGE', " 28 دن کی تبدیلی ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_BLOCKED', "جملہ واچ نے سپیمرز ہٹس کو آج بلاک کیا ہے، کل: %d");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_ADDRESSES', "بلاکڈ آئی پی ایڈریسز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_SETTINGS', "اینٹی-سپیم کی ترتیب");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRAFFIC_AJAX', " ٹریفک کو اپ ڈیٹ کرتا ہے، سوائے نقشوں کےAJAX");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_HISTORY_PREVIOUS', "پیچھے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_NEXT', "آگے");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/** additional translation for 1.2.11 for countries in more rows */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_MAX_COLUMNS', "ممالک کے کالمز کی تعداد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_MAX_ROWS', "ممالک کی قطاروں کی تعداد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_NAMES', "ملک کا نام دکھائے کہ نہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_FLAGS_FIRST', "پہلے پرچم دکھائے، پھر فیصد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* ExtraWatch 1.2.14 translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_GOALS_GET_INVERSED', "کی الٹی شرطGET");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_INVERSED', "کی الٹی شرطPOST");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE_INVERSED', " عنوان کی الٹی شرط");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_USERNAME_INVERSED', "یوزر نیم کی کی الٹی شرط");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_CAME_FROM_INVERSED', " جہاں سے آئےکی الٹی شرط");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATS_MAP', " تازہ ترین وزٹ میپ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_ENTER_KEY', "آخری وزٹ میپ ظاہر کرنے کے لیے یہ لکھیں <a href='http://www.ipinfodb.com/register.php' target='_blank'>ipinfodb.com</a> ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_STORE_KEY', "سٹور کی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_INVALID_KEY', "مہربانی کر کے مستند ipinfodb  کی درج کریں جو آپ نے ادھر سے حاصل کی ہے <a href='http://www.ipinfodb.com/register.php' target='_blank'>ipinfodb.com</a>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZEQUERY_BAD_REQUEST', "  بری درخواست");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_VISIT_SUBMITED_FIELDS', "جمع شدہ فارم کی فیلڈز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_URL_PARAMETERS', "یو آر ایل پیرامیٹرز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_ADD_PAGE', " ہدف کے طور پر صفحہ شامل کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_BLOCK_IP', " ایڈریس کو بلاک کریں IP اس ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_SUBMITED_FROM_VARIABLE', " اس جمع شدہ فارم کے ویریبل کو گول کے طور پرایڈ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_URL_PARAMETER_GOAL', " یو آر ایل پیرامیٹرکو گول کے طور پر ایڈ کریں اس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_TREND_EMPTY', "خالی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_NOT_NUMBER', "خبردار :  آپ نے جس ویلیو کا اندراج کیا ہے وہ ایک ہندسہ نہیں ہے۔ جملہ واچ ٹھیک طرح سے کام نہیں کرے گا");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EVALUATION_LEFT', "&nbsp;  یہ 15 دن کا ایویلوایشن ورژن ہے۔%d دن باقی ہیں۔ مہربانی کر کے اپنی ڈومین کے لیے جملہ واچ کا تا حیات لائسنس خریدیں اس کے لیے اور آنے والے ورژنز کے: <a href='http://www.codegravity.com/donate/extrawatch/' target='_blank'> جملہ واچ لائسنس کا تا حیات  </a> ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRIAL_VERSION_EXPIRED', " آپکے عارضی ورژن کی معیاد ختم ہو گئی ہے۔ برائے مہربانی جملہ واچ خریدیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CONFIG_LICENSE_ACTIVATED', "  لائسنس کامیابی سے فعال ہو گیا ہے۔ آپکا شکریہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CONFIG_LICENCE_DONT_MATCH', "غلط : لائسنس کی اورآپکی ڈومین میچ نہیں کرتے۔ کیا آپ نےیہی ڈومین کا نام ڈونیشن فارم میں لکھا تھا جو آپ نیچے دیکھ رہے ہیں؟ درست کی کے لیے درخواست کریں یا رابطہ کریں : support@codegravity.com<br/>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_VIEW_ADMINBODY_LONG_MESSAGE', "اگر آپ کافی دیر سے یہی پیغام دیکھ رہے ہیں تو آپکی لائیو سائٹ شائد غلط ہے۔  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    components/com_extrawatch/config.php اس کو اوپن کریں  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    کمنٹ ختم کریں اور اپنی اصل لائیو سیٹ کریں:  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    define('EXTRAWATCH_LIVE_SITE', 'http://www.codegravity.com');");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_ADMINBODY_LIVE_SITE', "خبردار: آپکے براوزر میں موجود سائٹ اور کنفیگیوریش میں لائیو سائٹ آپس میں نہیں ملتیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINBODY_SET_LIVE_SITE', "لائیو سائٹ کو %s پر سیٹ کریں اور جاری رکھیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_ADMINHEADER_JW', "جملہ واچ ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_REMOVE_BACKLINK', "بیک لنک کو ختم کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_KNOWLEDGE_BASE', "علمی بنیاد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_FLOW', "بہاو");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_GRAPHS', "گرافس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_COMPONENTS', "کمپوننٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_REVIEW', "ریویو");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_WRITE', "لکھیں ایک ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_FLOW_TRAFFIC', "ٹریفک کا بہاو");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_SELECT_PAGE', "صفحہ منتخب کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_OUTG_LINKS', "روٹ کے بیرونی لنکس کی تعداد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_NESTING', "نیسٹنگ کا لیول");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_SCALE', "پیمانہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_COMERCIAL_AD_FREE', "اشتہارات سے پاک ورژن");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_THANK_DONATION', "عطیہ دینے کے لیے آپ کا بہت شکریہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_REGISTRATION_KEY', "آپ کی%s ڈومین کی رجسٹریشن کی یہ ہے ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_BACKLINKS_REMOVE', "اب آپ بیک لنک کو ختم کر سکتے ہیں یا جملہ واچ کا لوگو چھپا سکتے ہیں فرنٹ اینڈ سے ترتیبات سے ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_SIZES_LAST_CHECK', "آخری چیک تب کیا گیا تھا:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_ADMINISTRATOR', "BLUE = Size of component/module in /administrator directory");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZECOMPONENTS_COMPONENT', "اجزاء");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_TOTAL', "مجموعہ:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_SIZE', "سائز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_REFRESH_ALL', "سب کو ریفریش کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZEDATABASE_TABLE', "ٹیبل");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_SIZE', "سائز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_1DAY', " 1 دن کی تبدیلی ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_7DAY', " 7 دن کی تبدیلی ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_28DAY', " 28 دن کی تبدیلی ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_NO_DATA', "کوئی ڈیٹا نہیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_TOTAL', "مجموعہ:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZEMODULES_REFRESH_ALL', " سب کو ریفریش کریں ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_TOTAL', "مجموعہ:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_MODULE', "موڈیول");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_SIZE', "سائز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZES_FILES', " فائلیں اور ڈائریکٹریاں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_BYTES', "بائٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_KB', "کلو بائٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_MB', "میگا بائٹس ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_GB', "گیگا بائٹس ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_REFRESH', "ریفریش");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATS_FOOTER', "ExtraWatch &copy;2006-%s by CodeGravity.com");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATUS_MB', "میگا بائٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE', "ڈیٹا بیس کے ٹیبل کا سائز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_DESC_IPINFODB_KEY', "آخری وزٹ کا میپ سے <a href='http://www.ipinfodb.com/register.php' target='_blank'>ipinfodb.com</a>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_FORCE_TIMEZONE_OFFSET', "ٹائم زون آف سیٹ کولازمی بنائیں ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


/* ExtraWatch 1.2.17 translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_UPDATE', "اپ ڈیٹ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_UPDATE_TITLE', " بیک اپ اور اپ گریڈ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_NA_IN_THIS_VERSION', "فری ورژن میں دستیاب نہیں، برائے مہربانی لائسنس ٹیب کو چیک کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SPAMWORD_BANS_ENABLED', "سپیم کے الفاظ کو فعال کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SPAMWORD_LIST', "سپیم کے الفاظ کی فہرست");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HIDE_REPETITIVE_TITLE', "Hide Repetitive Title");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_VISITS', "وزٹس کو مختصر کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_STATS', "اعداد و شمار کو مختصر کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_GOALS', "گولز کو مختصر کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LIMIT_BOTS', "  بوٹس  کو محدود کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LIMIT_VISITORS', " وزیٹرز کو محدود کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_WIDTH', "ٹول ٹپ کی چوڑائی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_HEIGHT', "ٹول ٹپ کی لمبائی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_URL', "URLٹول ٹپ کی ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_ONCLICK', "ٹول ٹپ کلک کرنے پر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IP_STATS', " کے اعدادوشمارIP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IPINFODB_KEY', "IP Info DB key ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ONLY_LAST_URI', "URI صرف آخری");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_FRONTEND_HIDE_LOGO', "فرنٹ اینڈ کا لوگو چھپائیں ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_NOFOLLOW', " فرنٹ اینڈ کو نو فالو کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_NO_BACKLINK', " فرنٹ اینڈ کے بیک لنک نو کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_USER_LINK', "فرنٹ یوزر کے لنکس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_FIRST', " فرنٹ اینڈ ممالک کا پہلا");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_NAMES', " فرنٹ اینڈ ممالک کا نام");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_UPPERCASE', " فرنٹ اینڈ ممالک بڑے حروف میں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_FLAGS_FIRST', " فرنٹ اینڈ ممالک کے پرچم کی فہرست");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_NUM', " فرنٹ اینڈ ممالک کا نمبر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_MAX_COLUMNS', " فرنٹ اینڈ ممالک کے زیادہ سے زیادہ کالم");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_MAX_ROWS', " فرنٹ اینڈ ممالک کی زیادہ سے زیادہ قطاریں ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TODAY', "آج کے فرنٹ اینڈ وزیٹرز ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_YESTERDAY', " کل کے فرنٹ اینڈ وزیٹرز ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_THIS_WEEK', " اس ہفتہ کے فرنٹ اینڈ وزیٹرز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_LAST_WEEK', " گزشتہ ہفتہ کے فرنٹ اینڈ وزیٹرز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_FRONTEND_VISITORS_THIS_MONTH', " اس ماہ کے فرنٹ اینڈ وزیٹرز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_LAST_MONTH', "گزشتہ ماہ کے فرنٹ اینڈ وزیٹرز ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL', " فرنٹ اینڈ وزیٹرز کا مجموعہ چھپائیں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL_INITIAL	', " فرنٹ اینڈ وزیٹرز کا مجموعہ ابتدائی ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_MAX_VALUES', "ہسٹری کی سب سے زیادہ ویلیوز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_MAX_DB_RECORDS', "ہسٹری کی سب سے زیادہ ریکارڈز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_UPDATE_TIME_VISITS', "ٹائم وزٹس کو اپ ڈیٹ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_UPDATE_TIME_STATS', "ٹائم سٹیٹس کو اپ ڈیٹ کریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAX_ROWS', "اعدادوشمار کی سب سے زیادہ قطاریں");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_HITS', " اعدادوشمار کی آئی پی ہٹس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MAXID_BOTS', " سے زیادہ آئی ڈی بوٹس زیادہ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MAXID_VISITORS', " سے زیادہ آئی ڈی ویزٹرز زیادہ ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEEP_DAYS', "اعدادوشمار رکھنے کے دن ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CACHE_FRONTEND_COUNTRIES', " فرنٹ اینڈ ممالک کا کیشے ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CACHE_FRONTEND_VISITORS', " فرنٹ اینڈ ویزٹرز کا کیشے ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_UNINSTALL_KEEP_DATA', "ان انسٹال کا رکھا جانیوالا ڈیٹا");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_IP', "کو نظر انداز کریں IP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_URI', "کو نظر انداز کریں URI");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_USER', "یوزرکو نظر انداز کریں ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BLOCKING_MESSAGE', "بلاکنگ کا پیغام");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SERVER_URI_KEY', "سرور کی یو آر آئی کی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL_INITIAL', " فرنٹ اینڈ وزیٹرز کا مجموعہ ابتدائی ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_RECORDS', "ریکارڈز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
/***********EDITs*****************/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_BLOCKING_TEXT', " بلاکنگ کو موثر بنانے کی لیے، آپ کوکسی بھی مواد یا فارمز سے پہلے جملہ واچ ایجنٹ کو شائع کرنے کی ضرورت ہے۔ مثلاً آپ کے ٹیمپلیٹ کی بائیں جانب.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    <br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    پر جا ئیں Module Manager -> ExtraWatch agent -> select position as left");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_EMAIL_SEO_REPORTS', " رپورٹسSEO");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEO_REPORTS_ENABLED', " کی شبانہ ای میل رپورٹس فعال ہوئیںSEO");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_WATCH_INSTALLATION_DEMO', "انسٹالیشن کی مثال دیکھیں ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/** JW 1.2.18 */
DEFINE('_EW_ADMINHEADER_HEATMAP', "Heatmap");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEATMAP_CLICKS', "clicks");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEATMAP_TITLE', "title");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEATMAP_CLICK_OPEN', "Click to open heatmap");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_NO_DATA', "This section contains no data yet ...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_POSITION', "Search result num.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BLOCKING_REASON', 'reason');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BLOCKING_UNAUTHORIZED_ACCESS', 'Unauthorized Access');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BLOCKING_BLOCKED_MANUALLY', 'Blocked manually');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BLOCKING_BAD_WORD', "bad word");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEATMAP_OF', "of");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_URI', "uri");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COUNT', "count");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SEO_REPORT_FOR', "SEO report for");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SEO_MOST_DYNAMIC_KEYPHRASES', "Most dynamic keyphrases");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SEO_MIN_POSITION', "min position");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SEO_AVG_POSITION', "average position");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SEO_MAX_POSITION', "max position");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SEO_CHANGE', "change");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SEO_DATE_OF_LAST_CHANGE', "date of last change");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SEO_TOTAL_VISITS_FROM_SEARCH_ENGINES', "Total visits by keyphrase from search engines");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOAL_ADD_SUBMITTED_VALUE', "Add submitted variable as goal");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_RENDERED_IN', "Rendered in");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SEO_RENDER_ONLY_CHANGED', "Render only values which were already used in previous days (have some percentage in change column)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SEO_REPORT_SETTINGS', "SEO Report Settings");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_HTTP500_ERROR', "Could not initialize ExtraWatch javascript functions! Browser could not load: \\n%s, because it returned HTTP 500 internal server error.  \\nThis usually of security restrictions by other components/plugins. Please check your .htaccess file in your root Joomla directory.  \\nIf you use Akeeba Admin tools, you need to go \ 'Akeeba htaccess maker\ ' -> \ 'Server Protection\ ' -> \ 'Exceptions\ ' -> \ 'Allow direct access to these files\ ', and add: \\n/components/com_joomlawatch/block.php \\n/components/com_joomlawatch/img.php \\n/components/com_joomlawatch/last.php \\n/components/com_joomlawatch/lastvisit.php \\n/components/com_joomlawatch/sizequery.php \\n/components/com_joomlawatch/sizequerytotal.php \\n/components/com_joomlawatch/stats.php \\n/components/com_joomlawatch/timezone.php \\n/components/com_joomlawatch/tooltip.php \\n/components/com_joomlawatch/trendtooltip.php \\n/components/com_joomlawatch/vars.php \\n/components/com_joomlawatch/visits.php \\n/components/com_joomlawatch/js/joomlawatch.js.php \\n/components/com_joomlawatch/js/maps.js.php ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_AGENT_NOT_PUBLISHED_ERROR_JOOMLA',"Warning: No visits are currently being recorded. Your ExtraWatch Agent module is published, but most probably in position which does not exist in your template.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                <br/><br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                To fix this: <br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                1. go to Modules section -&gt; ExtraWatch Agent <br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                2. change the Position to 'left' or 'footer' (or some other position).<br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                3. check if new visits are being recorded  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                <br/><br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                If this won't help, you can also: <br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                1. set 'Show Title' to 'Yes' in  Modules section -&gt; ExtraWatch Agent <br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                2. try to use some other positions of ExtraWatch agent module<br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                3. save<br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                4. after reload of your main page look for 'ExtraWatch Agent' text.<br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                5. this way you'll make sure the Agent module is published.<br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                6. after that you can set 'Show Title' back to 'No'.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                ");
/** Goals/Import IP */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS', "Goals");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_IMPORT', "Import goals");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_IMPORT_XML', "Import XML");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_EXPORT', "Export goals");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_FILENAME', "Select goals previously exported as XML");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_IMPORT_CSV', "import anti-spam ip csv");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_AGENT_NOT_PUBLISHED_ERROR_WORDPRESS',"Warning: No visits are being recorded. You must go to Appearance->Widgets section, <br/>find ExtraWatchAgent widget and drag&drop it to some of the containers on the right side. <br/>You can publish also other ExtraWatch modules this way. <br/><br/>Check the demonstration video:<br/><br/><iframe id='video-player' width='800' height='468' src='http://www.youtube.com/embed/uu_luBKJ8jI?enablejsapi=1&autoplay=1&rel=0&modestbranding=1&showinfo=0&showsearch=0&vq=hd1080' frameborder='0' allowfullscreen></iframe><br/><br/>In case of any questions about installation or problems, you can take advantage of our support on <a href='http://www.extrawatch.com' target='_blank'>http://www.extrawatch.com</a>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


/** 2.1 */
DEFINE('_EW_MENU_DOWNLOADS', "Downloads");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_FILE_NOT_FOUND', "FILE NOT FOUND");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_HTACCESS_NOT_WRITABLE', "Your .htaccess is not Writable.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_HTACCESS_COULD_NOT_BE_CREATED', ".htaccess could not be created, Please create your own.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_ADD_EXTENSION', "Add Extension");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_EXTENSION_NAME', "Extension Name");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_WARNING', "<b>Warning:</b> always backup your .htaccess file before adding new extension or path! Do not add 'php' as monitored extension. <br/>Be also careful with adding png/jpg, the download count will be increased once someone opens your page which contains images with this extension.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_ADD_FILE_PATH', "Add File/Path");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_FILE_PATH_NAME', "File/Path Name");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_DOWNLOAD_MONITOR', "Download Monitor");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_EXTENSIONS_BEING_MONITORED', "Extensions Being Monitored");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_FILES_PATHS_BEING_MONITORED', "Files/Paths Being Monitored");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_EDIT_EXTENSION', "Edit Extension");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_EDIT_FILE_PATH', "Edit File/Path");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_EXTENSION', "Extension");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_ACTION', "Action");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_PATH', "Path");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_TODAY', "Today");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_YESTERDAY', "Yesterday");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_THIS_WEEK', "This Week");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_LAST_WEEK', "Last Week");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_THIS_MONTH', "This Month");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_LAST_MONTH', "Last Month");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_INCOMPLETE', "The required Information is incomplete");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATS_SOCIAL_MEDIA', "Media");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_AVAILABLE_IN_PRO',"Available in PRO version");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_TOTAL',"Total Downloads");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


/** 3.0 - hosted version */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_CLICKED_ELEMENT_XPATH_CONDITION', "xpath of clicked element condition");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_CLICKED_ELEMENT_XPATH_CONDITION', "xpath of clicked element condition");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATS_DEVICES', "Mobile Devices");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_BLOCKED_BASED_ON_GOAL',"Blocked based on goal no. %s");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_TIME_BETWEEN_VISITS',"Total time spent");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LEFT_WEBSITE',"Left website");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_USERS',"Users");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_USERS_BLOCK_IP_CONFIRM',"Do you really want to block this IP address?");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_USERS_SHARING_HEADER',"Users sharing same login");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_USERS_SHARING_DESC',"Contains users who accessed the website from different IP addresses and/or from different country but with same login. This might be a warning for you, that they're sharing their account with someone else.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_USERS_ACTIVITY_HEADER',"Latest user activity");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
define('_EW_DESC_SEO_LIST_ENCRYPTED_KEYWORDS', "Google hides passing particular keywords from google search to websites. This will reveal the keyword's position,<br/> but not the keyword itself. Enable this option if you want to see also position of these encrypted keywords in stats.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SEO_MOST_POPULAR_KEYPHRASES',"Most popular keyphrases");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SEO_MOST_POPULAR_KEYPHRASES_DESC',"These are the keyphrases by which was your website found. You can copy this list and use it with some 3rd party service, which will give you an overview of SERP (Search Engine Rank Position). You can then optimize your website using SEO techniques,	and watch the increase of traffic in right upper side of main dashboard - displayed as a cyan bar");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_USERS_ALERT_EMAIL_SUBJECT',"Alert - user '%s' uses different IP address: '%s'");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_USERS_ALERT_EMAIL_CONTENT',"You can block this user from ExtraWatch Users section");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MAX_RECORDS',"Displaying max. %d records");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_DESC_USERS_SEND_ALERT_EMAILS',"If checked, you'll get an email once user uses different IP. This can help you to detect immediately, which user shares his login with someone else. Useful, if you're using paid accounts.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SEO_SHOW_ALL_TIME_REPORT', "Do not filter by particular dates, show all time SEO report");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_DOWNLOADS_ALLOW_ONLY_REFERRER', "Allow only when referred from: ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_ALLOWED_REFERRER', "Allowed Referrer");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_NOT_ALLOWED',"File download restricted by ExtraWatch rule. Please contact: %s");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_DOWNLOADS_EMAIL_RESTRICTED_SUBJECT',"Download restricted for IP: %s");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_EMAIL_RESTRICTED_BODY',"Someone from IP: %s attempted to download file: %s referred from %s, but it's restricted by ExtraWatch download referrer check");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_ADMINHEADER_CLICK_AREAS', "Click Areas");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_NO_TITLE','No Title');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CLICK_HEATMAP_FOR','Click Heatmap for ');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CLICK_AREAS_FOR','Clicks Areas for ');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_GOALS_SEND_EMAIL','Send an email');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_SEND_EMAIL','You will get an email everytime the goal has been reached. Email address is taken from "Emails" section.');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOAL_EMAIL_SUBJECT', "Goal '%s' was achieved, count: %d");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_GOAL_REACHED', " Goal '%s' was reached");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_DOWNLOADS_TOTAL_WEEKLY', "Total weekly");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ACTIVE', "active");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOAD_PRO', "Download PRO version");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_HEATMAP_CLICK_COUNT', "Total clicks today: %d");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEATMAP_LOADING','Loading Heatmap table ...');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_INVALID_EXTENSION', "Invalid extension type, .csv expected");   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_NUM_IP_FROM_CSV_IMPORTED', "Imported %d IP addresses from .csv file"); DEFINE('_EW_MENU_AVAILABLE_IN_PRO_HEATMAP', "(Available in PRO version) With our most accurate Heat Map, you can monitor user clicks and see the hottest click areas of your web and optimize the content accordingly");   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_AVAILABLE_IN_PRO_CLICK_AREAS', "(Available in PRO version) With Click Areas monitoring you can track clicks on buttons, links and improve the click rate");   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_AVAILABLE_IN_PRO_SEO_REPORT', "(Available in PRO version) Position of your web links on search engines");   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_AVAILABLE_IN_PRO_USERS', "(Available in PRO version) User Activity monitoring");   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_AVAILABLE_IN_PRO_FLOW', "(Available in PRO version) Interactive chart with internal traffic distribution");   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_AVAILABLE_IN_PRO_DOWNLOADS', "(Available in PRO version) See charts of downloads of zip, pdf or other downloadable artifacts");   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_AVAILABLE_IN_PRO_STATUS', "(Available in PRO version) Database table sizes monitoring");   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_AVAILABLE_IN_PRO_COMPONENTS', "(Available in PRO version) Directories size monitoring");   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_SEARCH_RANK', "Search Rank");   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DOWNLOADS_START_ADD_EXT', "No download statistics currently recorded. Start monitoring file downloads and");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
