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

defined('_JEXEC') or die('Ограничен достъп');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

//ExtraWatch language file - to create a new language file, just copy the english.php to eg. german.php and place into./components/com_extrawatch/lang/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Main Menu.
DEFINE('_EW_MENU_STATS', "Статистика");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_GOALS', "Цели");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_SETTINGS', "Настройки");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_CREDITS', "Благодарности");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_FAQ', "Често задавани въпроси");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_DOCUMENTATION', "Документация");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_LICENSE', "Лиценз");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_DONATORS', "Дарители");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_SUPPORT', "Поддържайте ExtraWatch и рекламите няма да се показват.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Left visitors real-time window.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_VISITORS', "Последни посетители");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_BOTS', "Ботове");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_CAME_FROM', "Идва от");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_MODULE_NOT_PUBLISHED', "Вашият модул JoomlaWach не е публикуван.За това не са записани никакви статистически данни. Отидете в раздел модули и да зададете модул ExtraWatch - да се публикува във всички страници");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_PANE_LOADING', "Зареждане...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Right stats window.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TITLE', "Статистика на посещенията през седмицата");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_WEEK', "Седмица");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_THIS_WEEK', "Тази седмица");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_UNIQUE', "Уникални");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADS', "Зареждания");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_HITS', "Хитове");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TODAY', "Днес");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_FOR', "за");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ALL_TIME', "За целият период");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_EXPAND', "Подробно");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_COLLAPSE', "Съкратено");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_URI', "Страници");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_COUNTRY', "Държави");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_USERS', "Потребители");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_REFERERS', "Препратки");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP', "IP адреси");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_BROWSER', "Браузер");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_OS', "ОС");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYWORDS', "Ключови думи");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_GOALS', "Цели");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TOTAL', "Общо");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_DAILY', "За определен ден");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_DAILY_TITLE', "Дневна статистика за");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ALL_TIME_TITLE', "Обща статистика");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADING', "Зареждане...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADING_WAIT', "Зареждане... моля изчакайте");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_TITLE', "Блокиран IP адрес");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_ENTER', "Въведете ръчно IP адреса, който искате да блокирате.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_MANUALLY', "Напишете IP адреса, който искате да блокирате. (напр. 217.242.11.54 или 217.* или 217.242.* за блокиране на обсега след звездичката)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_TOGGLE', "Превключване на блокирани IP адреси");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_PANE_LOADING', "Зареждам статистиката...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Settings.
DEFINE('_EW_SETTINGS_TITLE', "Настройки");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_DEFAULT', "Стандартни");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_SAVE', "Запомни");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_APPEARANCE', "Външен вид");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_FRONTEND', "Изглед на сайта");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_HISTORY_PERFORMANCE', "История и изпълнения");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ADVANCED', "Разширения");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_IGNORE', "Игнориране");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_BLOCKING', "Блокиране");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_EXPERT', "Експерт");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_CONFIRM', "Наистина ли искате да възстановите всички статистически данни и посетители?");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_ALL', "Възстановяване на всички данни");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_ALL_LINK', "Възстановяване на всички статистически данни &amp; и посетители");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_LANGUAGE', "Език");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_SAVED', "Настройките бяха съхранени");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ADD_YOUR_IP', "Добавете Вашия IP адрес");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_TO_THE_LIST', "в списъка");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Other / mostly general.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TITLE', "AJAX монитор за Joomla");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BACK', "Назад");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ACCESS_DENIED', "Нямате права за достъп");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LICENSE_AGREE', "Съгласен съм с настоящите условия &amp; и условията по-горе");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LICENSE_CONTINUE', "Продължи");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SUCCESS', "Операцията приключи успешно");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_RESET_SUCCESS', "Всички статистически данни и данни за посетителите бяхя изтрити");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_RESET_ERROR', "Данните не бяха изтрити, нещо не се получи");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CREDITS_TITLE', "Благодарности");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRENDS_DAILY_WEEKLY', "Дневни и седмични статистически данни за:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_1', "AJAX достъп отхвърлен: Моля, разгледайте статистиката на домейна, който сте посочили в configuration.php на Джумла");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_2', "Може би просто сте забравили да въведете WWW. преди името на домейна в браузъра. Javascript търси съдържание ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_3', "от");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_4', "това го принуждава да си мисли,че това е друг домейн");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Header.
DEFINE('_EW_HEADER_DOWNLOAD', "Вземете най-новия код на това разширение от");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEADER_CAST_YOUR', "Изпратете своя");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEADER_VOTE', "глас");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Tooltips.
DEFINE('_EW_TOOLTIP_CLICK', "Кликнете за да отворите tooltip прозореца");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_MOUSE_OVER', "Отидете с мишката на tooltip за да отворите прозореца");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_YESTERDAY_INCREASE', "Увеличение &apos; от вчера");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_HELP', "Отвари онлайн помощ за");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_WINDOW_CLOSE', "Затвори този прозорец");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_PRINT', "Печат");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Goals.
DEFINE('_EW_GOALS_INSERT', "Добавяне на нова цел");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_UPDATE', "Редактиране на цел номер");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ACTION', "Действие");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE', "Заглавие на Нова цел");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_NEW', "Нова цел");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_RELOAD', "Обновяване");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ADVANCED', "Разширено");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_NAME', "Име");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ID', "id");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_URI_CONDITION', "URI състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_URI_INVERSED', "URI обратно състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_GET_VAR', "GET променлива");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_GET_CONDITION', "GET състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_VAR', "POST променлива");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_CONDITION', "POST състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE_CONDITION', "Заглавие-състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_USERNAME_CONDITION', "Потребителско име-състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_IP_CONDITION', "IP състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_IP_INVERSED', "IP обратно състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_CAME_FROM_CONDITION', "Идва от състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_BLOCK', "Блокирай");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_REDIRECT', "Пренасочи на URL");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_HITS', "Посещения");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ENABLED', "Разрешени");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_EDIT', "Редактиране");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_DELETE', "Изтриване");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_DELETE_CONFIRM', "Вие ще загубите всички съществуващи статистически данни за тази цел. Наистина ли искате да изтриете всичко?");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Frontend.
DEFINE('_EW_FRONTEND_COUNTRIES', "Държава");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS', "Посетители");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_TODAY', "Днес");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_YESTERDAY', "Вчера");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_THIS_WEEK', "Тази седмица");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_LAST_WEEK', "Миналата седмица");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_THIS_MONTH', "Този месец");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_LAST_MONTH', "Миналият месец");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_TOTAL', "Общо");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Settings description - quite long.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_DEBUG', "ExtraWatch е в debug режим. По този начин ще могат да се определят причините за грешки. За да изключите, моля, променете стойността EXTRAWATCH_DEBUG в /components/com_extrawatch/config.php от 1 на 0");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_MAX_ROWS', "Максимален брой на редовете на данни след декомпресия в областта на статистиката");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_IP_HITS', "Всички IP адреси, които имат по-малко хитове от предишните дни, ще бъдат изтрити от историята на IP адреси.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_URL_HITS', "Всички URL адреси, които са по-малко хитове от предишните дни, ще бъде заличена от историята URL адреси.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_IP', "Игнориране на IP адрес в статистиката.Всеки адрес отделно на нов ред. Можете да използвате звездичка. <br/>Например. 192.* ще игнорира 192.168.51.31, 192.168.16.2, и т.н..");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UPDATE_TIME_VISITS', "Продължителност на подновяване на посетителите в левия панел, в милисекунди, по подразбиране 2000, бъдете внимателни с тази настройка.За да има ефект, обновете през администрацията интерфейса в ExtraWatch.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UPDATE_TIME_STATS', "Продължителност на подновяване на статистиката в десния панел в милисекунди, стандартно 2000, бъдете внимателни с тази настройка. а да има ефект, обновете през администрацията интерфейса в ExtraWatch.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_MAXID_BOTS', "Колко записа да се съхраняват в базата данни.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_MAXID_VISITORS', "Колко записа на посетителите да се съхраняват в базата данни.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LIMIT_BOTS', "Колко записа да се виждат в левия панел в администраторския интерфейс.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LIMIT_VISITORS', "Колко посетителите да се виждат в левия панел в администраторския интерфейс.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_VISITS', "Максимум символи, които ще бъдат показани при дълги заглавия и URI адреси");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_STATS', "Максимум символи, които ще да бъдат показани при дълги заглавия в десния статистически панел");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_KEEP_DAYS', "Брой дни, през които да се запази общата история на статистическите данни в базата данни. 0 = безкрайност.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TIMEZONE_OFFSET', "Ако сте в различна часова зона от сървъра ви, на който хоствате сайта си.(Въведете положително или отрицателно число, като разликата в часова зона)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_WEEK_OFFSET', "Промяната в рамките на седмицата, Timestamp/(3600*24*7) връща номера на седмицата от 1.1.1970, тази промяна е корекция на седмицата, започваща с понеделник. При нормални случаи, не е необходимо да се променя.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_DAY_OFFSET', "Промяната в рамките на деня, Шimestamp/(3600*24) връща датата на деня от 1.1.1970, тази промяна е корекция, за да започва денят от 00:00. При нормални случаи, не е необходимо да се променя");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_HIDE_LOGO', "<b>(Функционира в безплатната версия)</b> Може да използвате празна икона 1x1px в началната страница");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IP_STATS', "Използване на IP адрес в статистиката. В някои страни, IP адреса се счита за лични данни. Използвайте на свой собствен риск.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HIDE_ADS', "Тази настройка скрива рекламите, ако те наистина ви дразнят.С поддържането им, Вие подкрепяте по-нататъшното развитие на този инструмент. Благодаря.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_ONCLICK', "Ако искате да се покажат непроверените в отделен прозорец карти и схеми, поставете курсора върху иконите, вместо да кликнете.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SERVER_URI_KEY', "По подразбиране тази настройка е 'REDIRECT_URL', ако използвате url rewriting, можете да промените на 'SCRIPT_URL' ако във вашата статистика се показва само index.php");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_BLOCKING_MESSAGE', "Съобщение, което показва допълнителна информация по някакъв повод, защо са тези потребители блокирани.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_WIDTH', "Ширина на прозореца в tooltip");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_HEIGHT', "Височина на прозореца в tooltip");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_URL', "Тук можете да напишете всякакъв адрес за визуализиране на посетителския IP адрес.{ip} ще бъде заменен от реалният IP адреса на потребителя. Например: http://somewebsite.com/query?iplookup={ip}");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_URI', "Можете да въведете всякакъв URI, които искате да бъде игнориран от статистика. Можете да използвате заместващи символи (* и ?) тук. Напр. : /freel?n* ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_NAME', "Задайте името на целта. Това име ще видите в статистиката.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_URI_CONDITION', "Това, което се намира непосредствено след адреса на вашия домейн. За http://www.codegravity.com/projects/ е URI: /projects/ (Пример: <b>/projects*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_GET_VAR', "GET променлива е обикновено това, което виждате в URL обикновено след  знака ? или & amp; например: http://www.codegravity.com/index.php?<u>име</u>u=peter&amp;<u>фамилия</u>=smith.Можете също да използвате <u>*</u> в това поле, за всички GET променливи.(Пример: <b>n*me</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_GET_CONDITION', "Тук можете да определите на какво да се равни променливата в предишното поле.(Пример: <b>p?t*r</b>) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_POST_VAR', "Нещо подобно, но спазвайте стойностите, вписани във формуляра. Така, че ако имате на уебсайта си формуляр, който има поле за въвеждане &lt;input type='text' name='<u>регистрация</u>' /&gt;. (Пример: <b>expert*ces</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_POST_CONDITION', "Стойност, която е равна на променливата в предходното POST поле. Напр. Искаме да видим дали потребителят е направил опит за въвеждане в полето стойност на Java.(Пример: <b>*java*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_TITLE_CONDITION', "Заглавие на страница, която да съответства. (Пример: <b>*freelance programmers*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_USERNAME_CONDITION', "Име на влезлият потребител, за когото целта се прилага. (Пример: <b>psmith*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_IP_CONDITION', "IP адрес, от който идва посетителят. (Пример: <b>201.9?.*.*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_CAME_FROM_CONDITION', "URL, от който идва посетителят. (Пример: <b>*www.google.*</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_REDIRECT', "Ако тези условия са изпълнени, можете да пренасочите потребителя  към адрес по Ваш избор. Има по-висок приоритет, отколкото 'блокиран': (Пример: <b>http://www.codegravity.com/chod-prec.html</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_GOALS', "Колко символа максимум да се показват в таблицата за дълги имена");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_NO_BACKLINK', "Препратката до codegravity.com, можете да промените тази настройка, но оценяваме, ако тя остане.Благодаря");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES', "Преглед на общата статистика в модула на сайта. Ако промените настройките, трябва да изчакате да изтече времето в CACHE_FRONTEND_  за да настъпят промените.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_FIRST', "Ако искате  да пренаредите реда на Посетители/Държави в модула на страницата. Махнете го, статистиката на Посетителите ще се покаже на първо място,а след това Държави.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_NUM', "Брой на държавите, които желаете да се показват в модула на сайта");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS', "Преглед на държавите в модула на сайта. Ако промените настройките, трябва да изчакате да изтече времето в CACHE_FRONTEND_  за да настъпят промените.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_COUNTRIES', "Време в секунди колко често да се актуализират статистическите данни на държавите в модула на сайта");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_VISITORS', "Време в секунди колко често да се актуализира статистиката за посетителите в модула на сайта");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TODAY', "Преглед на посетителите на сайта за: Днес. Ако промените настройките, трябва да изчакате да изтече времето в CACHE_FRONTEND_  за да настъпят промените.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_YESTERDAY', "Преглед на посетителите на сайта за: Вчера. Ако промените настройките, трябва да изчакате да изтече времето в CACHE_FRONTEND_  за да настъпят промените.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_THIS_WEEK', "Преглед на посетителите на сайта за: Тази седмица. Ако промените настройките, трябва да изчакате да изтече времето в CACHE_FRONTEND_  за да настъпят промените.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_LAST_WEEK', "Преглед на посетителите на сайта за: Миналата седмица. Ако промените настройките, трябва да изчакате да изтече времето в CACHE_FRONTEND_  за да настъпят промените.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_THIS_MONTH', "Преглед на посетителите на сайта за: Този месец. Ако промените настройките, трябва да изчакате да изтече времето в CACHE_FRONTEND_  за да настъпят промените.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_LAST_MONTH', "Преглед на посетителите на сайта за: Миналият месец. Ако промените настройките, трябва да изчакате да изтече времето в CACHE_FRONTEND_  за да настъпят промените.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TOTAL', "Преглед на посетителите на сайта Общо след инсталацията на ExtraWatch. Ако промените настройките, трябва да изчакате да изтече времето в CACHE_FRONTEND_  за да настъпят промените.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LANGUAGE', "Езиков файл, който ще използвате. Езиковите файлове се намират в /components/com_extrawatch/lang/. За да добавите нов език, първо се уверете, че той вече не е на страниците на този проект. Ако там го няма, копирайте english.php и го преименувайте на mojjazyk.php например и го поставете на по-горния адрес. Преведете всички изрази в дясно. Най-добре е да използвате кодировка UTF-8");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS', "Целите Ви позволяват да се определят специални параметри. Ако с тези параметри сте съгласни, производителността на брояча се увеличава. По този начин можете да наблюдавате дали един посетител е посещавал специфични URL, дали е изпратил конкретна стойност във формуляра, има специфично име или идва от някой адрес. Можете да блокирате такъв посетител или да го пренасочете към специален URL адрес.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_INSERT', "Във всички полета освен имена може да използвате символите * и ?. Например: ?ear (комбинира: near, tear, ..),  p*r (комбинира: pr, peer, pear ..) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_BLOCK', "Настроите на 1, ако искате да блокирате даден посетител, който отговаря на критериите. Няма да виждате останалата част от съдържанието на сайта, само съобщение за неговото блокиране - без пренасочване, и неговия IP адрес ще бъде добавен към списъка на блокираните в статистиката. (Пример: <b>1</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* new translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY_CONDITION', "Изисквания на дадената държава");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY_INVERSED', "Държави обратно състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_COUNTRY_CONDITION', "Двубуквеният код на дадена държава (Напр.: <b>TH</b>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_INTERNAL', "Вътрешен");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_FROM', "От");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TO', "До");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ADD_TO_GOALS', "Добави цел");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_ADD_GOAL_COUNTRY', "Добави цел за тази държава");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_REPORT_BUG', "Напиши за грешки или дай предложение");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY', "Държава");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


/* translations 1.2.8b_12 */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_UPPERCASE', "Ако искате имената на държавите да са изписани с главни букви на сайта (Напр.: GERMANY, UNITED KINGDOM вместо Germany, United Kingdom)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_USERS', "Време в секунди колко често да се актуализират статистическите данни на потребителите в сайта");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TOTAL_INITIAL', "Първоначална стойност 'Общо:' на сайта. Полезно, ако сте преминали от друг статистически инструмент. (Напр. 20000). Ако не искате да използвате тази функция попълнете 0.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_USER', "Игнорирай потребителите от този textbox. Потребителско име он-лайн. (Напр.: myself {нов ред} mark_*) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_USERS_MOST', "Най-активните потребители към днешна дата от общият брой");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SPAMWORD_BANS_ENABLED', "Включва блокиране на изброените спам думи, показани по-долу?");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SPAMWORD_LIST', "Най-използваните спам думи, използвани в спам ботове. Можете да използвате * и ?. (Напр.: ph?rmac*).Ако в настройките по-горе е разрешено, ExtraWatch ще провери дали атакуващия изпратен формуляр ( HTTP POST заявка) към сайта Ви съвпада с една от тези думи. (Прилага се само за сайт под Joomla – форуми, коментари, това е доста ефективен начин за премахване на спам ботове, които се опитват да изпращат всякакви възможни формуляри.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ANTI_SPAM', "Анти-Спам");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_USER_LINK', "Линка, намиращ се в лицевия потребителски модул, който Ви позволява да посочите специфичен URL,който е отворен, когато потребителят кликне върху потребителското си име. Трябва да съдържа низа {user}, който ще бъде заменен с истинското име на потребителя. (Напр. index.php?option=com_comprofiler&task=userProfile&user={user}) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* translations 1.2.11b */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYPHRASE', "Ключови фрази");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HISTORY_MAX_VALUES', "Максимални стойности в раздела История(Example: <i>100</i>)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_ONLY_LAST_URI', "В посещенията показвай само последната посетена страница, не всички");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HIDE_REPETITIVE_TITLE', "В посещенията скрий повтарящи се заглавия на посетени вече страници");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HISTORY_MAX_DB_RECORDS', "Максимален брой на посетителите, които да се запазят в базата данни - История на посещенията. Бъдете внимателни с тази настройка, ако имате голям трафик, може да расте много по-бързо. Винаги проверявайте статуса колко данни се съдържат в таблицата за Историята .");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UNINSTALL_KEEP_DATA', "Включете таблиците в базата данни за деинсталиране. Изберете тази опция, преди да деинсталирате, ако правите ъпгрейд и искате да запазите данните си.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* email reports */
DEFINE('_EW_DESC_EMAIL_REPORTS_ENABLED', "Ще получите всяка вечер имейли с отчети за предходния ден, които можете да прочетете на сутринта");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_REPORTS_ADDRESS', "Имейл  адреса, на който ще получите тези отчети");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_PERCENT_HIGHER_THAN', "Доклади само за включените редове в електронната поща, когато този процент е по-висока от {value}. Задайте 0, ако не искате да ползвате тази функция <i>(example: 5)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_ONE_DAY_CHANGE_POSITIVE', "Включва само <b> за един ден </b> положителна промяна на стойността в имейла за отчитане на по-висок  {value} процент. Задайте 0, ако не искате да ползвате тази функция <i>(example: 5)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_ONE_DAY_CHANGE_NEGATIVE', "Включва само <b> за един ден </b> отрицателна промяна на стойността в имейла за отчитане на по-нисък {value} процент. Задайте 0, ако не искате да ползвате тази функция <i>(example: -10)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEVEN_DAY_CHANGE_POSITIVE', "Включва само <b> за седем дни </b> положителна промяна на стойността в имейла за отчитане на по-висок  {value} процент. Задайте 0, ако не искате да ползвате тази функция <i>(example: 2)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEVEN_DAY_CHANGE_NEGATIVE', "Включва само <b> за седем дни </b> отрицателна промяна на стойността в имейла за отчитане на по-нисък {value} процент. Задайте 0, ако не искате да ползвате тази функция <i>(example: -13)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_TWENTY_EIGHT_DAY_CHANGE_POSITIVE', "Включва само <b> за тридесет дни </b> положителна промяна на стойността в имейла за отчитане на по-висок  {value} процент. Задайте 0, ако не искате да ползвате тази функция <i>(example: 2)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_TWENTY_EIGHT_DAY_CHANGE_NEGATIVE', "Включва само <b> за тридесет дни </b> отрицателна промяна на стойността в имейла за отчитане на по-нисък {value} процент. Задайте 0, ако не искате да ползвате тази функция <i>(example: -13)</i>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_NOFOLLOW', "<b>(Функционира в PRO версия)</b> Активирайте тази настройка, ако искате да направите връзката с логото чрез атрибута rel='nofollow' ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_NAME_TRUNCATE', "Максимален брой знаци на ред за име на имейла. Променете броя, ако Вашия имейл прозорец за съобщения е твърде малък");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* email reports - sergej*/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_ENABLED', "Отчет имейли");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_ADDRESS', "Имейл адрес");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_NAME_TRUNCATE', "Максимален размер за име на имейла");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_PERCENT_HIGHER_THAN', "Доклади за включените редове");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_ONE_DAY_CHANGE_POSITIVE', "Включи само за един ден положителната промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_ONE_DAY_CHANGE_NEGATIVE', "Включи само за един ден отрицателна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_SEVEN_DAY_CHANGE_POSITIVE', "Включи само за седем дни положителна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_SEVEN_DAY_CHANGE_NEGATIVE', "Включи само за седем дни отрицателна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_TWENTY_EIGHT_DAY_CHANGE_POSITIVE', "Включи само за тридесет дни положителна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_TWENTY_EIGHT_DAY_CHANGE_NEGATIVE', "Включи само за тридесет дни отрицателна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
/* email reports - sergej*/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_MENU_HISTORY', "История");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_EMAILS', "Имейли");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_STATUS', "Статус");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_BLOCKED', "Тези IP адреси са били блокирани от анти-спам");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_VISITORS', "История за посетителите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_SHOWING_ONLY', "Показани са само %d от последните записи.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                За да промените тази стойности, отидете в Настройки -&gt; История &amp; Изпълнение -&gt; HISTORY_MAX_DB_RECORDS. Бъдете внимателни, тази настройка влияе върху времето за зареждане на данните по-долу.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_BUG', "Докладвай за грешки");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_FEATURE', "Искане за елемент");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_CAME_FROM_KEYWORDS', "Ключови думи");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BLOCKING_UNBLOCK', "Деблокиране");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYPHRASE ', "Ключовата дума");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_TABLE_NAME', "Име на таблицата");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_ROWS', "Редове");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_DATA', "Данни");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_TOTAL', "Общо");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS', "Имейл доклади");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORT_GENERATED', "Генериран доклад за филтрирани имейли от вчера");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_VALUE_FILTERS', "Имейл стойност на филтрите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_VALUE', "Стойност");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_PERCENT', "Процент");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_1DAY_CHANGE', "1-дневна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_7DAY_CHANGE', "7-дневна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_28DAY_CHANGE', "28-дневна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_BLOCKED', "ExtraWatch е блокирал %d спамър попадения днес, общо: %d");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_ADDRESSES', "Блокирани IP адреси");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_SETTINGS', "Анти-спам настройки");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRAFFIC_AJAX', "AJAX трафик на актуализациите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_PREVIOUS', "Предишна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_NEXT', "Следваща");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/** additional translation for 1.2.11 for countries in more rows */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_MAX_COLUMNS', "Брой колони на държавите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_MAX_ROWS', "Брой редове на държавите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_NAMES', "Показване името на държавата или не");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_FLAGS_FIRST', "Покажи знамената, а след това процента");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* ExtraWatch 1.2.14 translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_GET_INVERSED', "GET инверсно състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_INVERSED', "POST инверсно състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE_INVERSED', "Заглавие-обратно състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_USERNAME_INVERSED', "Потребителско име обратно състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_CAME_FROM_INVERSED', "Идва от обратно състояние");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP', "Карта на последното посещение");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_ENTER_KEY', "Моля, въведете <a href='http://www.ipinfodb.com/register.php' target='_blank'> ipinfodb.com </A> за да се появи последното посещение и карта:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_STORE_KEY', "Ключ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_INVALID_KEY', "Моля, въведете валиден ключ, получен от: <a href='http://www.ipinfodb.com/register.php' target='_blank'>ipinfodb.com</a>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEQUERY_BAD_REQUEST', "Грешно искане:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_SUBMITED_FIELDS', " Изпратени области във формата:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_URL_PARAMETERS', " URL параметри:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_ADD_PAGE', " Добави страница като цел");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_BLOCK_IP', " Блокиране на този IP адрес");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_SUBMITED_FROM_VARIABLE', " Добавете тази изпратена форма на променливата като цел");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_URL_PARAMETER_GOAL', "Добави този URL параметър като цел");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TREND_EMPTY', "Празен");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_NOT_NUMBER', " ВНИМАНИЕ: Въведената стойност не е число. ExtraWatch няма да работи нормално!");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EVALUATION_LEFT', "&nbsp; Това е 15-дневна пробна версия. Дни в ляво: <b>%d</b>. Моля, закупете през този период от <a href='http://www.codegravity.com/donate/extrawatch/' target='_blank'>ExtraWatch лиценз за Вашия домейн</a> за тази и предстоящите версии.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRIAL_VERSION_EXPIRED', " Вашата пробна версия е изтекла. Моля закупете лиценз за ExtraWatch");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CONFIG_LICENSE_ACTIVATED', "Лиценза е активиран успешно. Благодаря Ви!");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CONFIG_LICENCE_DONT_MATCH', "<b>Грешка: лицензния ключ и домейна Ви не съвпадат.</b><br/>Въвели ли сте едно и също име на домейна във формата, която виждате по-долу? Моля свържете се с : support@codegravity.com");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VIEW_ADMINBODY_LONG_MESSAGE', "Ако виждате съобщението по-горе, като прекалено дълго, Вашия сайт може да бъде грешен.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    Отворете /com_extrawatch/config.php  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    и напишете адреса на сайта Ви, напр.:  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    define('EXTRAWATCH_LIVE_SITE', 'http://www.codegravity.com');");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINBODY_LIVE_SITE', "Забележка: сайта в браузъра и сайта в конфигурацията: %s и %s не съвпадат.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINBODY_SET_LIVE_SITE', "Задайте сайта, за да: %s и продължете...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_JW', "ExtraWatch");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_REMOVE_BACKLINK', "Премахване на Backlink");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_KNOWLEDGE_BASE', "База знания");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_FLOW', "Поток");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_GRAPHS', "Графики");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_COMPONENTS', "Компоненти");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_REVIEW', "Преглед");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_WRITE', "Добави");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_TRAFFIC', "Поток на трафика ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_SELECT_PAGE', "Изберете страница:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_OUTG_LINKS', "Root изходящи броя връзки:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_NESTING', "Ниво:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_SCALE', "Скала:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_AD_FREE', "Безплатна версия");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_THANK_DONATION', "Благодаря Ви много за дарението!");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_REGISTRATION_KEY', "Регистрационният ключ за Вашия домейн %s е: ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_BACKLINKS_REMOVE', "Сега можете да премахнете или скриете ExtraWatch логото в интерфейса от настройките");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_COMPONENT', "Компонент");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_TOTAL', "Общо:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_SIZE', "Размер");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_REFRESH_ALL', "Обнови всичко");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_TABLE', "Таблица");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_SIZE', "Размер");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_1DAY', "1-дневна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_7DAY', "7-дневна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_28DAY', "28-дневна промяна");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_NO_DATA', "Няма данни");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_TOTAL', "Общо:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_REFRESH_ALL', "Обнови всичко");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_TOTAL', "Общо:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_MODULE', "Модул");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_SIZE', "Размер");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_FILES', "Файлове &amp; Директории");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_BYTES', "Байта");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_KB', "KB");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_MB', "MB");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_GB', "GB");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_REFRESH', "Обнови");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_FOOTER', "ExtraWatch &copy;2006-%s by CodeGravity.com");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_MB', "MB");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IPINFODB_KEY', "Карта на последното посещение от: <a href='http://www.ipinfodb.com/register.php' target='_blank'>ipinfodb.com</a>");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_FORCE_TIMEZONE_OFFSET', "Сила по часови зони");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* ExtraWatch 1.2.17 translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_UPDATE', "Актуализация");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_UPDATE_TITLE', "Резервно копие & Актуализация");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_NA_IN_THIS_VERSION', "Не се предлага в безплатната версия, моля проверете раздела за лиценза");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SPAMWORD_BANS_ENABLED', "Включи Спам думи");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SPAMWORD_LIST', "Списък със Спам думи");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HIDE_REPETITIVE_TITLE', "Скриване на повтарящи се заглавия");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_VISITS', "Ограничаване на посещенията");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_STATS', "Ограничаване на статистиката");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_GOALS', "Ограничаване на целите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LIMIT_BOTS', "Лимит на ботовете");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LIMIT_VISITORS', "Лимит на посетителите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_WIDTH', "Ширина на Tooltip");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_HEIGHT', "Височина Tooltip");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_URL', "URL на Tooltip");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_ONCLICK', "Tooltip OnClick");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IP_STATS', "IP статистика");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IPINFODB_KEY', "IP информация за DB ключ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ONLY_LAST_URI', "Само последен URI");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_HIDE_LOGO', "Скрий логото");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_NOFOLLOW', "Връзката с логото");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_NO_BACKLINK', "Препратка");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_USER_LINK', "Потребителски връзки");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_FIRST', "Първо държавите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_NAMES', "Имената на държавите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_UPPERCASE', "Имената на държавите с главни букви");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_FLAGS_FIRST', "Първо знамената на държавите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_NUM', "Брой на държавите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_MAX_COLUMNS', "Брой колони");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_MAX_ROWS', "Брой редове");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TODAY', "Посетители днес");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_YESTERDAY', "Посетители вчера");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_THIS_WEEK', "Посетители през тази седмица");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_LAST_WEEK', "Посетители през последната седмица");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_THIS_MONTH', "Посетители през този месец");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_LAST_MONTH', "Посетители през последния месец");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL', "Скрий Общо посетители");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL_INITIAL	', "Общо първоначално");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_MAX_VALUES', "Максимални стойности");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_MAX_DB_RECORDS', "Максимален брой записи");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_UPDATE_TIME_VISITS', "Актуализация на посещенията");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_UPDATE_TIME_STATS', "Актуализация на статистиката");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAX_ROWS', "Максимален брой редове");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_HITS', "Максимален брой IP хитове");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MAXID_BOTS', "Максимален брой записи");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MAXID_VISITORS', "Максимален брой посетители");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEEP_DAYS', "Максимален брой дни за съхранение");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CACHE_FRONTEND_COUNTRIES', "Кеш държави");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CACHE_FRONTEND_VISITORS', "Кеш посетители");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CACHE_FRONTEND_USERS', "Кеш потребителите");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
/* sergej */
DEFINE('_EW_LANGUAGE', "Активен език");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_UNINSTALL_KEEP_DATA', "Деинсталиране на запазените данни");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
/* sergej*/
DEFINE('_EW_IGNORE_IP', "Игнориране на IP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_URI', "Игнориране на URI");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_USER', "Игнориране на Потребител");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BLOCKING_MESSAGE', "Блокиране на Съобщение");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SERVER_URI_KEY', "Сървър URI ключ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL_INITIAL', "Първоначален брой посетители");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_RECORDS', "Записи");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
/***********EDITs*****************/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_BLOCKING_TEXT', " За да се блокира ефективно, трябва да публикувате ExtraWatch agent преди всякакво съдържание или форми. Напр. на лявата страна във Вашия шаблон.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    <br/>  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                   Отиди в Модул мениджъра -> ExtraWatch agent -> изберете позиция като ляво");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_SEO_REPORTS', "SEO доклади");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEO_REPORTS_ENABLED', "SEO имейл доклади всяка вечер");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_WATCH_INSTALLATION_DEMO', "Вижте Демо инсталация");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
/* sergej */
DEFINE('_EW_EMAIL_SEO_REPORTS_ENABLED', "Включи SEO доклади");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

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
