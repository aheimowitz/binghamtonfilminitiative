<?php

/**
 * JoomlaWatch - A real-time ajax joomla monitor and live stats  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @package JoomlaWatch  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @version @VERSION@  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @revision @REVISION@  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @license http://www.gnu.org/licenses/gpl-3.0.txt 	GNU General Public License v3  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @copyright (C) @YEAR@ by CodeGravity.com - All rights reserved!  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 * @website http://www.codegravity.com  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 */

defined( '_JEXEC' ) or die( 'Restricted access: ' );  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

//JoomlaWatch language file - to create a new language file, just copy the english.php to eg. german.php and place into /components/com_joomlawatch/lang/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Main Menu
DEFINE('_EW_MENU_STATS', "آمار زنده");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_GOALS', "اهداف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_SETTINGS', "تنظیمات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_CREDITS', "دستاندرکاران");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_FAQ', "راهنما");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_DOCUMENTATION', "مستندات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_LICENSE', "مجوز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_DONATORS', "حامیان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_SUPPORT', "جهت حذف تبلیغات از بخش مدیریت سایتتان از سیستم آمارگیری پشتیبانی به عمل آورید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


// Left visitors real-time window  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_VISITORS', "آخرین بازدیدکنندگان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_BOTS', "ربات ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_CAME_FROM', "آمده از");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_MODULE_NOT_PUBLISHED', "ماژول سیستم آمارگیری در سایت شما منتشر نشده است! هیچ آمار جدیدی ذخیره نمی شود. جهت انتشار آن، به بخش مدیریت ماژول ها رفته و آن را در همه صفحات منتشر نمایید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_PANE_LOADING', "در حال بارگذاری بازدیدها...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Right stats window  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TITLE', "مشاهده آمار هفته");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_WEEK', "هفته");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_THIS_WEEK', "هفته جاری");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_UNIQUE', "منحصر به فرد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADS', "بار");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_HITS', "بازدید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TODAY', "امروز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_FOR', "برای");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ALL_TIME', "تمام وقت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_EXPAND', "بازکردن");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_COLLAPSE', "بستن");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_URI', "صفحات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_COUNTRY', "کشورها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_USERS', "اعضا");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_REFERERS', "ارجاع دهنده ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP', "آی پی ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_BROWSER', "مرورگرها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_OS', "سیستم عامل ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYWORDS', "کلمات کلیدی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_GOALS', "اهداف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TOTAL', "مجموع");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_DAILY', "روزانه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_DAILY_TITLE', "آمار روزانه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ALL_TIME_TITLE', "آمار کلی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADING', "در حال بارگذاری...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADING_WAIT', "در حال بارگذاری... لطفاً صبر نمایید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_TITLE', "مسدود کردن آی پی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_ENTER', "روود آی پی به صورت دستی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_MANUALLY', "آدرس آی پی مورد نظر را جهت مسدود کردن وارد نمایید. (به طور مثال 217.242.11.54 یا 217.* یا 217.242.* جهت مسدود کردن همه ی آی پی های مطابق)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_TOGGLE', "ضامن واقعی مسدود سازی آی پی ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_PANE_LOADING', "در حال بارگذاری آمار...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Settings
DEFINE('_EW_SETTINGS_TITLE', "تنظیمات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_DEFAULT', "پیشفرض");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_SAVE', "ذخیره");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_APPEARANCE', "ظاهر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_FRONTEND', "سمت کاربری سایت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_HISTORY_PERFORMANCE', "تاریخچه و عملکرد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ADVANCED', "پیشرفته");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_IGNORE', "نادیده گرفتن");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_BLOCKING', "مسدود کردن");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_EXPERT', "تخصصی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_CONFIRM', "آیا از تنظیم مجدد همه ی آمار و اطلاعات بازدیدکنندگان مطمئن هستید؟");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_ALL', "تنظیم مجدد همه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_ALL_LINK', "تنظیم مجدد همه ی آمار و اطلاعات بازدیدکنندگان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_LANGUAGE', "زبان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LANGUAGE', "زبان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_SAVED', "تنظیات ذخیره شد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ADD_YOUR_IP', "اضافه کردن آی پی شما");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_TO_THE_LIST', "به لیست.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Other / mostly general  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TITLE', "سیستم لحظه ای مانیتورینگ سایت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BACK', "بازگشت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ACCESS_DENIED', "شما اجازه دسترسی به این صفحه را ندارید!");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LICENSE_AGREE', "من با شرایط و ضوابط بالا موافقم");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LICENSE_CONTINUE', "ادامه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SUCCESS', "عملیات موفقیت آمیز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_RESET_SUCCESS', "تمامی اطلاعات آماری و بازدیکندگان با موفقیت پاک سازی شد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_RESET_ERROR', "شکست در پاک سازی اطلاعات، مشکلی وجود دارد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CREDITS_TITLE', "دستاندرکاران");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRENDS_DAILY_WEEKLY', "آمار روزانه و هفتگی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_1', "مجوز AJAX داده نشده است: لطفا آمار و اطلاعات را از دامنه ای که در فایل configuration.php سایتتان مشخص کرده اید مشاهده نمایید - ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_2', "شاید فراموش کرده اید که حروف www. را در ابتدای نام دامنه خود استفاده کنید. جاوا  اسکریپن شما در حال تلاش برای دسترسی است ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_3', "از");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_4', "چه چیزی باعث اشتباه شدن در تشخیص دامنه می شود.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Header
DEFINE('_EW_HEADER_DOWNLOAD', "دریافت آخرین کد افزونه از");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEADER_CAST_YOUR', "لطفا نظر خود را");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEADER_VOTE', "بنویسید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Tooltips
DEFINE('_EW_TOOLTIP_CLICK', "جهت مشاهده توضیحات کلیک کنید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_MOUSE_OVER', "جهت مشاهده توضیحات نشانگر موس را روی آن عبور دهید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_YESTERDAY_INCREASE', "افزایش روز گذشته");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_HELP', "بازکردن راهنمای خارجی برای");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_WINDOW_CLOSE', "بستن این پنجره");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_PRINT', "چاپ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Goals
DEFINE('_EW_GOALS_INSERT', "درج هدف جدید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_UPDATE', "بروزرسانی کی هدف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ACTION', "عملیات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE', "هدف جدید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_NEW', "هدف جدید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_RELOAD', "بارگذاری مجدد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ADVANCED', "پیشرفته");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_NAME', "نام");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ID', "شناسه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_URI_CONDITION', "شرایط آدرس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_URI_INVERSED', "معکوس شرایط  آدرس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_GET_VAR', "متغیرهای فرم از طریق GET");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_GET_CONDITION', "شرایط دریافت متغیرهای فرم از طریق GET");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_VAR', "متغیرهای فرم از طریق POST");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_CONDITION', "شرایط دریافت متغیرهای فرم از طریق POST");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE_CONDITION', "شرایط عنوان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_USERNAME_CONDITION', "شرایط نام کاربری");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_IP_CONDITION', "شرایط آی پی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_IP_INVERSED', "معکوس شرایط  آی پی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_CAME_FROM_CONDITION', "شرایط محلی که کاربر از آنجا آمده");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_BLOCK', "مسدودسازی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_REDIRECT', "انتقال به آدرس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_HITS', "بازدید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ENABLED', "فعال");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_EDIT', "ویرایش");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_DELETE', "حذف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_DELETE_CONFIRM', "تمامی آمار اخیر مربوط به این هدف حذف خواهد شد. آیا در مورد حذف این هدف مطمئن هستید؟");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Frontend
DEFINE('_EW_FRONTEND_COUNTRIES', "کشورها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS', "بازدیدکنندگان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_TODAY', "بازدید امروز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_YESTERDAY', "بازدید دیروز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_THIS_WEEK', "بازدید این هفته");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_LAST_WEEK', "بازدید هفته قبل");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_THIS_MONTH', "بازدید این ماه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_LAST_MONTH', "بازدید ماه قبل");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_TOTAL', "بازدید کُل");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Settings description - quite long  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_DEBUG', "سیستم آمار گیری در حالت خطایابی می باشد. در این حالت شما می توانید علت خطا را کشف نمایید. جهت غیرفعال کردن این حالت، لطفا مقدار JOOMLAWATCH_DEBUG را در /components/com_joomlawatch/config.php از 1 به 0 تغییر دهید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_MAX_ROWS', "حداکثر ردیف ها جهت نمایش در جالت نمایش آمار به صورت گسترش یافته.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_IP_HITS', "تمامی آی پی هایی که بازدید آن ها در روزهای قبل کمتر از این مقدار باشند، از تاریخچه آی پی ها حذف خواهند شد.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_URL_HITS', "تمامی آدرس هایی که بازدید آن ها در روزهای قبل کمتر از این مقدار باشند، از تاریخچه آی پی ها حذف خواهند شد.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_IP', "مثتثنی کردن آی پی های خاصی از آمار گیری. هر آی پی را در خطی جداگانه وارد نمایید. در اینجا می توانید از کد های عمومی استفاده نمایید. <br/>مثال: *.192 برای مثتثنی کردن آی پی های 192.168.51.31, 192.168.16.2, و غیره..");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UPDATE_TIME_VISITS', "زمان تازه سازی آمار بازدیدکنندگان بر حسب میلی ثانیه، پیشفرض 2000 می باشد، در تغییر این گزینه دقت نمایید. سپس صفحه ی مدیریت سیستم آمارگیری را مجدد بارگذاری نمایید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UPDATE_TIME_STATS', "زمان به روز رسانی آمار بر حسب میلی ثانیه، پیشفرض 4000 می باشد، در تغییر این گزینه دقت نمایید. سپس صفحه ی مدیریت سیستم آمارگیری را مجدد بارگذاری نمایید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_MAXID_BOTS', "تعداد بازدیدهای روبات ها که در پایگاه داده ذخیره خواهد شد.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_MAXID_VISITORS', "تعداد بازدیدهای واقعی ها که در پایگاه داده ذخیره خواهد شد.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LIMIT_BOTS', "تعداد روبات هایی که در بخش مدیریت نمایش داده می شود.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LIMIT_VISITORS', "تعداد بازدیدکنندگان واقعی که در بخش مدیریت نمایش داده می شود.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_VISITS', "حداکثر کاراکترها جهت نمایش در آدرس ها و عناوین بلند.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_STATS', "حداکثر کاراکترها جهت نمایش در پنل آمار سمت راست.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_KEEP_DAYS', "تعداد روزها جهت نگهداری آمار آن ها در پایگاه داده، 0 = نامحدود.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TIMEZONE_OFFSET', "هنگامی که شما در یک منطقه زمانی متفاوت از سرور میزبانی خود می باشید. (مقدار مثبت یا منفی بر حسب ساعت)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_WEEK_OFFSET', "انحراف زمان هفته، مقدار timestamp/(3600*24*7)   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
شماره هفته را از 1.1.1970 می دهد، این تغییر برای تنظیم هفته جهت شروع از دوشنبه می باشد ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_DAY_OFFSET', "انحراف زمان ساعت، مقدار timestamp/(3600*24) که شماره روز را از 1.1.1970 می دهد، این تغییر برای تنظیم شروع زمان از ساعت 00:00 می باشد ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_HIDE_LOGO', "<b>(مخصوص نسخه حرفه ای)</b> برای استفاده از یک آیکون خالی 1x1px در سایت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IP_STATS', "فعال سازی آمارهای آدرس آی پی. در برخی کشورها نگهداری آی پی در پایگاه داده برای یک مدت طولانی ممنوع می باشد. با مسئولیت خودتان از این گزینه استفاده نمایید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HIDE_ADS', "این تنظیم، تبلیغات را در قسمت مدیریت در صورتی که واقعا شما را آزار می دهد حذف می کند. با نگهداشتن آن شما از طراحی این ابزار پشتیبانی می کنید. از شما متشکریم");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_ONCLICK', "در صورتی که می خواهید تولتیپ ها با قرار گرفتن موس روی متن به جای کلیک بر روی آن نمایش داده شوند، این گزینه را غیرفعال نمایید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SERVER_URI_KEY', "به صورت پیشفرض 'REDIRECT_URL' می باشد، مقدار استاندارد در هنگام استفاده از بازنویسی آدرس ها می باشد، همچنین در صورتی که فقط صفحه index.php را گزارش گیری می کند می تواند 'SCRIPT_URL' باشد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_BLOCKING_MESSAGE', "پیامی که به کاربر مسدود شده و یا برای کسب اطلاعات که چرا شما این کاربران را مسدود کرده اید نمایش داده می شود.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_WIDTH', "عرض تولتیپ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_HEIGHT', "ارتفاع تولتیپ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_URL', "جهت نمایش مشخصات آی پی بازدیدکننده می توانید هر لینک را اینجا قرار دهید. عبارت {ip} با آی پی بازدیدکننده جایگزین خواهد شد. مثال: {http://somewebsite.com/query?iplookup={ip");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_URI', "نادیده گرفتن آدرس هایی که می خواهید در آمارگیری نادیده گرفته بشوند. می توانید از کد های عمومی (* و ?) استفاده نمایید. مثال: *freel?n/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
 ");
DEFINE('_EW_DESC_GOALS_NAME', "نامی را برای هدف در اینجا تعیین نمایید. این نام را شما در آمار خواهید دید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_URI_CONDITION', "هر چیزی که بعد از نام دامنه شما می باشد. به طور مثال برای http://www.codegravity.com/projects/ آدرس می شود: /projects/ (نمونه برای استفاده: <b>/projects*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_GET_VAR', "متغیر GET، متغیری هست که شما در آدرس صفحه معمولا بعد از یک ? یا علامت &amp; دیده می شود. مثال:<br/> http://www.codegravity.com/index.php?<u>name</u>=peter&amp;<u>surname</u>=smith<br/> همچنین می توانید علامت <u>*</u> را در این فیلد برای اسکن همه متغیرهای get استفاده نمایید. (نمونه برای استفاده: <b>n*me</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_GET_CONDITION', "در اینجا شما می بایستی یک مقدار مقدار مطابق برای یک مقدار از فیلد قبلی وارد نمایید. (نمونه برای استفاده: <b>p?t*r</b>) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_POST_VAR', "کاملا یکسان می باشد، اما ما مقادیر ارسال شده از یک فرم را بررسی می کنیم. بنابراین یک فرم در سایت شما دارای فیلدی مانند <b dir=ltr > &lt;input type='text'   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
name='<u>experiences</u>' /&gt; </b>  می باشد. (نمونه برای استفاده: <b>exper*ces</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_POST_CONDITION', "مطابقتی برای مقدار از این فیلد نوع POST. مثال:  ما می خواهیم ببینیم که آیا کاربر java استفاده کرده است. (نمونه برای استفاده: <b>*java*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_TITLE_CONDITION', "عنوان صفحه که باید مطابقت کند. (نمونه برای استفاده: <b dir=ltr>*freelance programmers*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_USERNAME_CONDITION', "نام یک عضو وارد سایت شده. (نمونه برای استفاده: <b dir=ltr>psmith*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_IP_CONDITION', "آی پی کاربری که آمده است: (نمونه برای استفاده: <b dir=ltr>201.9?.*.*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_CAME_FROM_CONDITION', "آدرسی صفحه ای که کاربر از آن آمده است. (نمونه برای استفاده: <b dir=ltr>*www.google.*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_REDIRECT', "کاربر به آدرسی ک شما مشخص کرده اید منتقل شده است. دارای اولویت بالاتری نسبت به 'مسدود کردن' می باشد.: (نمونه برای استفاده: <b>http://www.codegravity.com/goaway.html</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_GOALS', "تعداد کاراکترها جهت حذف از جدول اهداف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_NO_BACKLINK', "<b>(مخصوص نسخه حرفه ای)</b> لینک به codegravity.com، که می توانید آن را غیرفعال نمایید،  ولی ما ممنون می شویم اگر آن را غیرفعال نکنید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES', "نمایش آمار کلی کشورها در ماژول. در صورت تغییر این مقدار، تاثیر آن بعد از زمان تنظیم شده در زمان کَش اثر خواهد کرد...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_FIRST', "در صورتی که می خواهید ترتیب نمایش بازدیدکنندگان و کشورها را تغییر دهید این گزینه را تغییر دهید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_NUM', "تعداد کشورها جهت نمایش در سایت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS', "نمایش بازدیدکنندگان کشورها در ماژول آمار بازدید. در صورت تغییر این مقدار، تاثیر آن بعد از زمان تنظیم شده در زمان کَش اثر خواهد کرد...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_COUNTRIES', "مقدار زمان کَش کردن مجموع کشورها در سایت برحسب ثانیه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_VISITORS', "مقدار زمان کَش کردن بازدیدکننده ها در سایت برحسب ثانیه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TODAY', "نمایش بازدیدکنندگان سایت برای: امروز. در صورت تغییر این مقدار، تاثیر آن بعد از زمان تنظیم شده در زمان کَش اثر خواهد کرد...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_YESTERDAY', "نمایش بازدیدکنندگان سایت برای: دیروز. در صورت تغییر این مقدار، تاثیر آن بعد از زمان تنظیم شده در زمان کَش اثر خواهد کرد...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_THIS_WEEK', "نمایش بازدیدکنندگان سایت برای: این هفته. در صورت تغییر این مقدار، تاثیر آن بعد از زمان تنظیم شده در زمان کَش اثر خواهد کرد...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_LAST_WEEK', "نمایش بازدیدکنندگان سایت برای: هفته گذشته. در صورت تغییر این مقدار، تاثیر آن بعد از زمان تنظیم شده در زمان کَش اثر خواهد کرد...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_THIS_MONTH', "نمایش بازدیدکنندگان سایت برای: این ماه. در صورت تغییر این مقدار، تاثیر آن بعد از زمان تنظیم شده در زمان کَش اثر خواهد کرد...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_LAST_MONTH', "نمایش بازدیدکنندگان سایت برای: ماه گذشته. در صورت تغییر این مقدار، تاثیر آن بعد از زمان تنظیم شده در زمان کَش اثر خواهد کرد...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TOTAL', "نمایش مجموع آمار بازدیدکنندگان سایت از هنگام نصب سیستم آمارگیری: امروز. در صورت تغییر این مقدار، تاثیر آن بعد از زمان تنظیم شده در زمان کَش اثر خواهد کرد...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LANGUAGE', "فایل زبان جهت استفاده. فایل های زبان در پوشه /components/com_joomlawatch/lang/ قرار دارند. در صورتی که می خواهید زبان جدیدی را اضافه نمایید، ابتدا سایت پروژه را بازدید نمایید و در صورتی که زبان مورد نظر موجود نمی باشد، فقط فایل زبان english.php را کپی نموده و به طور مثال به farsi.php تغییر دهید و در پوشه فایل های زبان قرار دهید. سپس، همه مقادیر اصلی را ترجمه نمایید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS', "بخش اهداف به شما امکان تعریف پارامترهای خاص را می دهد. در صورتی که شرایط این پارامتر ایجاد شود، شمارنده هدف افزایش می یابد. با این روش شما می توانید آمار بازدید کاربران از یک آدرس خاص، ارسال یک مقدار خاص، آمار یک کاربر خاص یا کاربرانی که از یک آدرس خاص می آیند را جمع آوری و بررسی نمایید. همچنین می توانید بعضی کاربران را مسدود یا به آدرس هایی دیگر منتقل نمایید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_INSERT', "در تمامی فیلد ها بجز نام شما می توانید از * و ? به عنوان عبارات عمومی استفاده نمایید. برای مثال: ?ear (مطابقت خواهد کرد با: near، tear، ..)،  p*r (مطابقت خواهد کرد با: pr, peer, pear ..) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_BLOCK', "در صورتی که می خواهید بازدیدکننده مسدود شود، مقدار 1 را وارد نمایید. کاربر مطالب را نخواهد دید،  و فقط پیامی که می گوید او کمسدود شده است می بیند - بدون هیچگونه تغییر مسیری و آی پی کاربر در آمار کاربران مسدود شده اضافه می شود (نمونه برای استفاده: <b>1</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* new translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY_CONDITION', "شرایط کشور");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_CONTRY_INVERSED', "معکوس شرایط  کشور");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_COUNTRY_CONDITION', "کد 2 حرفی کشور با حروف بزرگ (مثال: <b>TH</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_INTERNAL',"داخلی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_FROM',"از");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TO',"به");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ADD_TO_GOALS',"افزودن به هدف ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_ADD_GOAL_COUNTRY',"افزودن هدف برای این کشور");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_REPORT_BUG',"گزارش خطا یا ویژگی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY',"کشور");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


/* translations 1.2.8b_12 */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_UPPERCASE',"نمایش نام کشورها با حروف بزرگ در سایت (مثال: GERMANY، UNITED KINGDOM به جای Germany، United Kingdom)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_USERS',"مقدار زمان کَش کردن اعضای سایت در سایت برحسب ثانیه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TOTAL_INITIAL', "مقدار اولیه مجموع آمار بازدید. این گزینه در هنگامی که از ابزارهای آمار بازدید دیگر نقل مکان می کنید مناسب می باشد. (مثال: 20000). جهت عدم استفاده از این ویژگی، مقدار 0 را وارد نمایید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_USER', "نادیده گرفتن کاربران لیست شده در این فهرست. هر کاربری را در یک خط وارد نمایید. (مثال: myself {خط بعدی} *_mark) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_USERS_MOST', "Most active users today from total   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
of");
DEFINE('_EW_DESC_SPAMWORD_BANS_ENABLED',"فعال کردن مسدودسازی بر اساس واژه های وارد شده در لیست زیر؟");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SPAMWORD_LIST',"بیشترین واژه های استفاده شده توسط روبات های هرزنامه. شما می توانید از عبارات عمومی در اینجا استفاده نمایید، (مثال: ph?rmac*).  در صورتی که تنظیمات بالا فعال باشد، سیستم آمارگیری پیشرفته بررسی خواهد کرد که آیا حمله کنندگان به سایت شما آیا در ارسال یک فرم (از طریق درخواست نوع HTTP POST request) روی سایت شما از برخی از این واژه های هرزنامه استفاده می کنند یا نه. (در فرم های اصلی سایت ، فروم، نظرات اعمال می شود و همچنین برای جلوگیری از بمباران هرزنامه ها به هر شکل ممکن موثر است)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ANTI_SPAM',"ضد هرزنامه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_USER_LINK',"لینکی در ماژول کاربران سیستم آمارگیری - که به شما امکان تعریف یک آدرس را می دهد، که در صورتی که کاربر روی نام کاربری های نمایش داده شده در ماژول کلیک کند، صفحه آن کاربر باز شود. این لینک باید دارای رشته {user} باشد که با نام کاربری کاربران جایگزین می شود. مثال: {index.php?option=com_comprofiler&task=userProfile&user={user");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* translations 1.2.11b */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYPHRASE', "عبارات کلیدی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HISTORY_MAX_VALUES', "حداکثر مقادیر در تب تاریخچه (به طور مثال: <i>100</i>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_DESC_ONLY_LAST_URI', "نمایش فقط آخرین صفحه بازدید شده در آمار بازدیدها به جای نمایش همه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HIDE_REPETITIVE_TITLE', "پنهان کردن نام سایت های تکراری در عنوان صفحات بازدید شده");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HISTORY_MAX_DB_RECORDS', "حداکثر تعداد بازدیدکنندگان جهت نگهداری در پایگاه داده برای تاریخچه بازدیدها. در استفاده از این گزینه مراقب باشید، چرا که در صورتی که ترافیک سایت شما زیاد باشد، حجم پایگاه داده سریعا زیاد خواهد شد. همیشه مقدار اطلاعاتی را که در جدول تاریخچه ذخیره می شود را بررسی نمایید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UNINSTALL_KEEP_DATA', "نگاه داشتن جداول پایگاه داده هنگام حذف افزونه. این گزینه را قبل از حذف افزونه در صورتی که می خواهید افزونه را به روز رسانی نمایید و می خواهید که اطلاعات را نگاه دارید، علامت بزنید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* email reports */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_REPORTS_ENABLED', "هر شب ایمیلی حاوی گزارشات روز گذشته دریافت خواهید کرد که می توانید هر روز صبح بخوانید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_REPORTS_ADDRESS', "آدرس ایمیلی که این گزارشات برایتان ارسال خواهد شد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_PERCENT_HIGHER_THAN', "ایمیل فقط شامل گزارشاتی باشد که درصد آن بیشتر از {value} باشد. مقدار 0 را جهت عدم استفاده از این ویژگی وارد نمایید. <i>(مثال: 5)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_ONE_DAY_CHANGE_POSITIVE', "ایمیل گزارشات فقط شامل مقادیر <b>مثبت یک روز</b> تغییر بیشتر از {value} درصد باشد. مقدار 0 را جهت عدم استفاده از این ویژگی وارد نمایید. <i>(مثال: 5)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_ONE_DAY_CHANGE_NEGATIVE', "ایمیل گزارشات فقط شامل مقادیر <b>منفی یک روز</b> تغییر بیشتر از {value} درصد باشد. مقدار 0 را جهت عدم استفاده از این ویژگی وارد نمایید. <i>(مثال: 10-)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEVEN_DAY_CHANGE_POSITIVE', "ایمیل گزارشات فقط شامل مقادیر <b>مثبت هفت روز</b> تغییر بیشتر از {value} درصد باشد. مقدار 0 را جهت عدم استفاده از این ویژگی وارد نمایید. <i>(مثال: 2)</i></i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEVEN_DAY_CHANGE_NEGATIVE', "ایمیل گزارشات فقط شامل مقادیر <b>منفی هفت روز</b> تغییر بیشتر از {value} درصد باشد. مقدار 0 را جهت عدم استفاده از این ویژگی وارد نمایید. <i>(مثال: 13-)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_TWENTY_EIGHT_DAY_CHANGE_POSITIVE', "ایمیل گزارشات فقط شامل مقادیر <b>مثبت بیشت و هشت روز</b> تغییر بیشتر از {value} درصد باشد. مقدار 0 را جهت عدم استفاده از این ویژگی وارد نمایید. <i>(مثال: 2)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_TWENTY_EIGHT_DAY_CHANGE_NEGATIVE', "ایمیل گزارشات فقط شامل مقادیر <b>منفی بیست و هشت روز</b> تغییر بیشتر از {value} درصد باشد. مقدار 0 را جهت عدم استفاده از این ویژگی وارد نمایید. <i>(مثال: 13-)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_DESC_FRONTEND_NOFOLLOW', "<b>(مخصوص نسخه حرفه ای)</b> در صورتی که می خواهید لینک لوگو با ویژگی عدم پیگیری 'rel='nofollow نمایش داده شود، این گزینه را فعال نمایید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_NAME_TRUNCATE', "حداکثر کاراکتر نام ایمیل. این گزینه را در صورتی که پنجره پیام ایمیل کاربر بسیار کوچک است، تغییر دهید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_MENU_HISTORY', "تاریخچه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_EMAILS', "ایمیل ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_STATUS', "وضعیت پایگاه داده");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_BLOCKED',"این آی پی ها توسط سیستم ضد هرزنامه مسدود شده اند");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_HISTORY_VISITORS',"تاریخچه بازدیدکنندگان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_SHOWING_ONLY', "در حال نمایش فقط %d رکورد آخر. جهت تغییر این مقدار، به قسمت تنظیمات -&gt; تاریخچه و عملکرد -&gt; حداکثر رکوردهای تاریخچه بروید . مراقب باشید، چرا که این تنظیمات زمان بارگذاری داده ها را تحت تاثیر قرار می دهد.  ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_BUG', "گزارش خطا");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_FEATURE', "درخواست ویژگی جدید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_VISITS_CAME_FROM_KEYWORDS',"کلمات کلیدی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_BLOCKING_UNBLOCK',"رفع مسدودی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYPHRASE ',"عبارات کلیدی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATUS_DATABASE_TABLE_NAME',"نام جدول");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_ROWS',"ردیف ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_DATA',"داده ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_TOTAL',"مجموع");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_EMAIL_REPORTS',"ایمیل گزارشات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORT_GENERATED',"گزارش فیلتر شده تولید شده از دیروز برای ایمیل");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_VALUE_FILTERS',"فیلترهای مقادیر ایمیل");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_VALUE',"مقدار");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_PERCENT',"درصد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_1DAY_CHANGE',"1 روز تغییر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_7DAY_CHANGE',"7 روز تغییر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_28DAY_CHANGE',"28 روز تغییر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_BLOCKED',"امروز سیستم آمارگیری پیشرفته %d آی پی را که احتمال بودن ارسال کننده هرزنامه را می داد مسدود کرده است، مجموع: %d");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_ADDRESSES',"آدرس های آی پی مسدود شده");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_SETTINGS',"تنظیمات ضد هرزنامه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRAFFIC_AJAX',"به روز رسانی ترافیک به صورت AJAX (به جز نقشه)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_HISTORY_PREVIOUS',"قبلی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_NEXT',"بعدی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/** additional translation for 1.2.11 for countries in more rows */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_MAX_COLUMNS',"تعداد ستون های فهرست کشورها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_MAX_ROWS',"تعداد سطرهای فهرست کشورها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_NAMES',"نمایش یا عدم نمایش نام کشورها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_FLAGS_FIRST',"نمایش پرچم ها در ابتدا، سپس مقادیر درصد ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* JoomlaWatch 1.2.14 translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_GOALS_GET_INVERSED', "معکوس شرایط  دریافت متغیرهای فرم از طریق GET");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_INVERSED', "معکوس شرایط  دریافت متغیرهای فرم از طریق POST");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE_INVERSED', "معکوس شرایط  عنوان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_USERNAME_INVERSED', "معکوس شرایط  نام کاربری");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_CAME_FROM_INVERSED', "معکوس شرایط  محلی که کاربر از آنجا آمده است");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATS_MAP', "نقشه آخرین بازدیدها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_ENTER_KEY',"لطفا کلید شناسایی حساب کاربری خود در سایت <a href='http://www.ipinfodb.com/register.php' target='_blank'>ipinfodb.com</a> را جهت نمایش نقشه آخرین بازدیدها وارد نمایید:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_STORE_KEY',"ذخیره سازی کلید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_INVALID_KEY',"لطفا کلید معتبر ipinfodb خود را که از سایت <a href='http://www.ipinfodb.com/register.php'   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
target='_blank'>ipinfodb.com</a> دریافت نموده اید، وارد نمایید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZEQUERY_BAD_REQUEST',"درخواست نادرست: ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_VISIT_SUBMITED_FIELDS',"فیلد های ارسال شده فرم:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_URL_PARAMETERS',"پارامترهای آدرس:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_ADD_PAGE'," افزودن این صفحه به عنوان هدف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_BLOCK_IP'," مسدود سازی این آدرس آی پی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_SUBMITED_FROM_VARIABLE'," افزودن این متغیر ارسال شده فرم به عنوان هدف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_URL_PARAMETER_GOAL'," افزودن این پارامترهای آدرس وب به عنوان هدف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_TREND_EMPTY',"خالی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_NOT_NUMBER'," اخطار: مقداری که وارد نموده اید یک عدد نمی باشد. با این مقدار سیستم آمارگیری به درستی عمل نخواهد کرد!");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EVALUATION_LEFT',"&nbsp; این نسخه یک نسخه آزمایشی 15 روزه می باشد. روزهای باقیمانده: <b>%d</b>. لطفا یک <a href='http://www.codegravity.com/donate/joomlawatch/'   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
target='_blank'>مجوز تمام وقت سیستم آمارگیری برای دامنه خود</a> برای این نسخه و نسخه های آینده خریداری نمایید.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRIAL_VERSION_EXPIRED'," زمان نسخه آزمایش شما به پایان رسیده است. لطفا سیستم آمارگیری را خریداری نمایید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_CONFIG_LICENSE_ACTIVATED',"مجوز استفاده با موفقیت فعال شد. از شما متشکریم.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CONFIG_LICENCE_DONT_MATCH',"<b>خطا: کلید مجوز و دامنه شما مطابقت نمی کنند.</b><br/>آیا نام دامنه را همانطور که در زیر می بینید در پرداختتان وارد نموده اید؟ <br/>لینک '<b>درخواست کلید فعال سازی درست</b>' را کلیک نمایید یا با info@codegravity.com تماس حاصل نمایید<br/>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_VIEW_ADMINBODY_LONG_MESSAGE',"اگر شما این پیام را برای مدتی طولانی در بالای سایت خود می بینید، بدین معنا است که سایت شما اشتباه می باشد. فایل components/com_joomlawatch/config.php را باز نمایید و مقدار متغیر آدرس سایتتان را درست وارد نمایید. مثال: define('JOOMLAWATCH_LIVE_SITE', 'http://www.codegravity.com');");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_ADMINBODY_LIVE_SITE',"اخطار: سایت در مرورگر شما و سایت در تنظیمات: %s و %s مطابقت نمی کنند.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINBODY_SET_LIVE_SITE',"تنظیم سایت به : %s و ادامه...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_ADMINHEADER_JW',"سیستم آمارگیری پیشرفته ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_REMOVE_BACKLINK',"حذف لینک بازگشت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_KNOWLEDGE_BASE',"پایگاه دانش");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_FLOW',"جریان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_GRAPHS',"نمودار ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_COMPONENTS',"کامپوننت ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_REVIEW',"نقد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_WRITE',"نوشتن یک ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_FLOW_TRAFFIC',"جریان ترافیک");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_SELECT_PAGE',"انتخاب صفحه:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_OUTG_LINKS',"تعداد لینک های خروجی ریشه:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_NESTING',"سطوح تودرتو:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_SCALE',"مقیاس:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_COMERCIAL_AD_FREE',"نسخه بدون تبلیغات");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_THANK_DONATION',"از کمک شما بسیار متشکریم!");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_REGISTRATION_KEY',"کلید ثبت نام برای دامنه شما %s : ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_BACKLINKS_REMOVE',"حالا شما می توانید لینک و لوگوی سیستم آمارگیری پیشرفته را در سایتتان از طریق قسمت تنظیمات حذف نمایید ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_SIZES_LAST_CHECK',"آخرین تاریخ بررسی:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_ADMINISTRATOR',"رنگ آبی = حجم کامپوننت/ماژول در پوشه administrator");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZECOMPONENTS_COMPONENT',"کامپوننت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_TOTAL',"مجموع:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_SIZE',"حجم");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_REFRESH_ALL',"تازه سازی همه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZEDATABASE_TABLE',"جدول");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_SIZE',"حجم");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_1DAY',"1 روز تغییر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_7DAY',"7 روز تغییر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_28DAY',"28 روز تغییر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_NO_DATA',"بدون تغییر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_TOTAL',"مجموع:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZEMODULES_REFRESH_ALL',"تازه سازی همه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_TOTAL',"مجموع:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_MODULE',"ماژول");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_SIZE',"حجم");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZES_FILES',"فایل ها و پوشه ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_BYTES',"بایت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_KB',"کیلوبایت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_MB',"مگابایت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_GB',"گیگابایت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_REFRESH',"تازه سازی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATS_FOOTER',"سیستم آمارگیری پیشرفته &copy;2006-%s");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATUS_MB',"مگابایت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE',"حجم جداول پایگاه داده سایت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_DESC_IPINFODB_KEY',"کلید شناسایی سایت ipinfodb.com  برای نقشه آخرین بازدیدها از: <a href='http://www.ipinfodb.com/register.php' target='_blank'>ipinfodb.com</a>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_FORCE_TIMEZONE_OFFSET',"اجبار انحراف منطقه زمانی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


/* JoomlaWatch 1.2.17 translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_UPDATE', "به روز رسانی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_UPDATE_TITLE', "پشتیبان گیری و به روز رسانی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_NA_IN_THIS_VERSION',"در نسخه رایگان موجود نمی باشد، لطفا تب مجوز را مشاهده نمایید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SPAMWORD_BANS_ENABLED', "فعال سازی مسدود سازی واژه های هرزنامه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SPAMWORD_LIST', "لیست واژه های هرزنامه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HIDE_REPETITIVE_TITLE', "مخفی کردن عنوان های تکراری");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_VISITS', "حذف بازدیدها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_STATS', "حذف آمار");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_GOALS', "حذف اهداف");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LIMIT_BOTS', "محدودیت روبات ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LIMIT_VISITORS', "محدودیت بازدیدکنندگان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_WIDTH', "عرض تولتیپ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_HEIGHT', "ارتفاع تولتیپ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_URL', "آدرس تولتیپ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_ONCLICK', "نمایش تولتیپ هنگام کلیک");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IP_STATS', "آمار آی پی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IPINFODB_KEY', "کلید شناسایی سایت IPInfoDB");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ONLY_LAST_URI', "فقط آخرین آدرس");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_FRONTEND_HIDE_LOGO', "پنهان کردن لوگو");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_NOFOLLOW', "عدم پیگیری");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_NO_BACKLINK', "بدون لینک بازگشت");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_USER_LINK', "لینک های اعضا");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_FIRST', "کشورها در ابتدا");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_NAMES', "نام کشورها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_UPPERCASE', "نام کشورها با حروف بزرگ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_FLAGS_FIRST', "پرچم کشورها در ابتدا ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_NUM', "تعداد کشورها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_MAX_COLUMNS', "حداکثر تعداد ستون های کشورها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_MAX_ROWS', "حداکثر تعداد سطرهای کشورها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TODAY', "بازدیدکنندگان امروز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_YESTERDAY', "بازدیدکنندگان دیروز");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_THIS_WEEK', "بازدیدکنندگان این هفته");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_LAST_WEEK', "بازدیدکنندگان هفته گذشته");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_FRONTEND_VISITORS_THIS_MONTH', "بازدیدکنندگان این ماه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_LAST_MONTH', "بازدیدکنندگان ماه گذشته");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL', "پنهان کردن مجموع بازدیدکنندگان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL_INITIAL	', "مقدار اولیه آمار بازدیدکنندگان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_MAX_VALUES', "حداکثر مقادیر تاریخچه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_MAX_DB_RECORDS', "حداکثر رکورد های تاریخچه");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_UPDATE_TIME_VISITS', "زمان به روز رسانی بازدیدها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_UPDATE_TIME_STATS', "زمان به روز رسانی آمار");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAX_ROWS', "حداکثر ردیف های آمار");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_HITS', "آمار بازدیدهای آی پی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MAXID_BOTS', "حداکثر روبات ها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MAXID_VISITORS', "حداکثر بازدیدکنندگان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEEP_DAYS', "روزهای نگه داری آمار ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CACHE_FRONTEND_COUNTRIES', "کَش آمار کشورها ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CACHE_FRONTEND_VISITORS', "کَش آمار بازدیدکنندگان ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_UNINSTALL_KEEP_DATA', "حذف داده های نگاه داشته شده ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_IP', "نادیده گرفتن IP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_URI', "نادیده گرفتن آدرس وب");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_USER', "نادیده گرفتن کاربر");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BLOCKING_MESSAGE', "پیام مسدود سازی");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SERVER_URI_KEY', "کلید URI سرور");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL_INITIAL', "مقدار اولیه آمار بازدیدکنندگان");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_RECORDS', "رکوردها");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
/***********EDITs******************/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_BLOCKING_TEXT'," برای اینکه مسدود سازی موثر باشد، شما می بایستی ماژول عامل سیستم آمارگیری را قبلی از هر محتوا یا فرمی منتشر نمایید. به طور مثال: در سمت چپ قالبتان.<br/>به قسمت مدیریت ماژول ها بروید -> ماژول عامل سیستم آمارگیری ->   	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
موقعیت را سمت چپ (left) انتخاب نمایید");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_EMAIL_SEO_REPORTS', "گزارشات SEO");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEO_REPORTS_ENABLED',"گزارشات ایمیلی شبانه SEO فعال شد");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_WATCH_INSTALLATION_DEMO',"مشاهده دموی نصب");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

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
