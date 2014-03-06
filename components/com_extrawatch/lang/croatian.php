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

defined('_JEXEC') or die('Ograničen pristup');  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

//ExtraWatch language file - to create a new language file, just copy the english.php to eg. german.php and place into./components/com_extrawatch/lang/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Main Menu.
DEFINE('_EW_MENU_STATS', "Statistika uživo");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_GOALS', "Ciljevi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_SETTINGS', "Postavke");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_CREDITS', "Credits");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_FAQ', "CPP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_DOCUMENTATION', "Dokumentacija");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_LICENSE', "Licenca");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_DONATORS', "Donatori");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_SUPPORT', "Podrži ExtraWatch i makni reklame sa backenda.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


// Left visitors real-time window.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_VISITORS', "Najnoviji posjetitelji");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_BOTS', "Botovi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_CAME_FROM', "Dolazi iz");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_MODULE_NOT_PUBLISHED', "Vas ExtraWatch module nije objavljen! Nove statistike se ne bilježe. Za objavljivanje idite na sekciju Moduli i objavite na svim stranicama");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_PANE_LOADING', "Učitavanje posjeta...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Right stats window.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TITLE', "Tjedna statistika posjetitelja.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_WEEK', "Tjedan");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_THIS_WEEK', "ovaj tjedan");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_UNIQUE', "jedinstveni");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADS', "opterećenja");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_HITS', "pregledi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TODAY', "danas");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_FOR', "za");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ALL_TIME', "Ukupno vrijeme");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_EXPAND', "proširi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_COLLAPSE', "uruši");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_URI', "Stranice");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_COUNTRY', "Države");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_USERS', "Korisnici");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_REFERERS', "Pozivatelji");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP', "IP adrese");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_BROWSER', "Preglednici");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_OS', "Operacijski sustavi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYWORDS', "Ključne riječi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_GOALS', "Ciljevi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TOTAL', "Ukupno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_DAILY', "Dnevno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_DAILY_TITLE', "Dnevna statistika");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ALL_TIME_TITLE', "Ukupna statistika");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADING', "učitavanje...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_LOADING_WAIT', "učitavanje... molimo pričekajte");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_TITLE', "IP blokiranje");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_ENTER', "Unesi IP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_MANUALLY', "Unesite IP koji želite blokirati. (npr. 217.242.11.54 ili 217.* ili 217.242.* za blokiranje svih IP adresa koje odgovaraju zamjenskom znaku)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_BLOCKING_TOGGLE', "Podešavanje blokiranja");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_PANE_LOADING', "Učitavanje statistike...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Settings.
DEFINE('_EW_SETTINGS_TITLE', "Postavke");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_DEFAULT', "Početne postavke");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_SAVE', "Spremi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_APPEARANCE', "Izgled");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_FRONTEND', "Frontend");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_HISTORY_PERFORMANCE', "Povijest &amp;amp; Performansa");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ADVANCED', "Napredno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_IGNORE', "Ignoriraj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_BLOCKING', "Blokiranje");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_EXPERT', "Najnaprednije");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_CONFIRM', "Želite li zaista poništiti podatke o posjetiteljima i statistiku?");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_ALL', "Poništi sve");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_RESET_ALL_LINK', "Poništi sve statistike &amp;amp; podatke posjetitelja");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_LANGUAGE', "Jezik");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_SAVED', "Postavke spremljene");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ADD_YOUR_IP', "Dodaj IP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_TO_THE_LIST', "na listu.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Other / mostly general.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TITLE', "AJAX joomla monitor uživo");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BACK', "Natrag");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ACCESS_DENIED', "Nemate ovlasti za pregledavanje ovog!");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LICENSE_AGREE', "Prihvaćam odredbe &amp;amp; uvjete korištenja");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LICENSE_CONTINUE', "Nastavak");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SUCCESS', "Rad uspješno obavljen");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_RESET_SUCCESS', "Statistike i podaci posjetitelja su uspješno obrisani");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_RESET_ERROR', "Podaci NISU uspješno obrisani, nešto je pošlo po krivu");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CREDITS_TITLE', "Zasluge");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRENDS_DAILY_WEEKLY', "Dnevna i tjedna statistika");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_1', "AJAX dozvola odbijena: Molimo pogledajte statistike domene koja je navedena u configuration.php joomle - ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_2', "Možda ste zaboravili www. ispred domene. Vas javascript pokušava pristupiti ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_3', "iz");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_AJAX_PERMISSION_DENIED_4', "zbog čega misli da je to druga domena.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Header.
DEFINE('_EW_HEADER_DOWNLOAD', "Preuzmite posljednji kod proširenja");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEADER_CAST_YOUR', "Molimo, dajte svoj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HEADER_VOTE', "glas");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Tooltips.
DEFINE('_EW_TOOLTIP_CLICK', "Kliknite za prikaz opisa alata");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_MOUSE_OVER', "Usmjerite pokazivač preko za pregled opisa alata");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_YESTERDAY_INCREASE', "jučerašnji porast");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_HELP', "Otvara online pomoć za");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_WINDOW_CLOSE', "Zatvori prozor");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_PRINT', "Printaj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Goals.
DEFINE('_EW_GOALS_INSERT', "Unesite novi cilj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_UPDATE', "Azurirajte cilj br.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ACTION', "Radnja");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE', "Novi cilj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_NEW', "Novi cilj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_RELOAD', "Učitaj ponovno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ADVANCED', "Napredno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_NAME', "Naziv");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ID', "id");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_URI_CONDITION', "URI uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_URI_INVERSED', "URI suprotan uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_GET_VAR', "GET varijabla");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_GET_CONDITION', "GET uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_VAR', "POST Varijabla");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_CONDITION', "POST uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE_CONDITION', "Uvjet naslova");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_USERNAME_CONDITION', "Uvjet korisničkog imena");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_IP_CONDITION', "IP uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_IP_INVERSED', "IP suprotan uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_CAME_FROM_CONDITION', "Dolazi iz uvjeta");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_BLOCK', "Blokiraj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_REDIRECT', "Preusmjeri na URL");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_HITS', "Sadržaj pregledan");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_ENABLED', "Omogućeno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_EDIT', "Uredi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_DELETE', "Obriši");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_DELETE_CONFIRM', "Izgubit ćete sve statističke podatke za ovaj cilj. Jeste li sigurni da želite obrisati cilj br.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Frontend.
DEFINE('_EW_FRONTEND_COUNTRIES', "Države");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS', "Posjetitelji");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_TODAY', "Danas");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_YESTERDAY', "Jučer");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_THIS_WEEK', "Ovaj tjedan");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_LAST_WEEK', "Prošli tjedan");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_THIS_MONTH', "Ovaj mjesec");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_LAST_MONTH', "Prošli mjesec");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_TOTAL', "Ukupno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

// Settings description - quite long.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_DEBUG', "ExtraWatch je u debug načinu rada. Ovim načinom možete otkriti uzrok grešaka. Za isključivanje ovog načina rada promijenite vrijednost EXTRAWATCH_DEBUG u /components/com_extrawatch/config.php sa 1 na 0");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_MAX_ROWS', "Najveći broj redova koji se prikazuju kad su statistike u proširenom načinu rada.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_IP_HITS', "Sve IP adrese koje prethodnih dana imaju manje pregleda od zadane vrijednosti bit će obrisane iz povijesti IP adresa.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_URL_HITS', "Svi URL-ovi koji prethodnih dana imaju manje pregleda od zadane vrijednosti bit će obrisane iz povijesti IP adresa.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_IP', "Izuzmi određenu IP adresu iz statistike. Razmaknuti novim redom. Možete koristiti zamjenske znakove. &lt;br/&gt;npr. 192.* će ignorirati 192.168.51.31, 192.168.16.2, itd..");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UPDATE_TIME_VISITS', "Vrijeme osvježavanja za posjetitelje u milisekundama, zadana vrijednost je 2000, oprez s ovim. Na kraju ponovno učitajte ExtraWatch backend.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UPDATE_TIME_STATS', "Vrijeme osvježavanja statistike u milisekundama,zadana vrijednost je 4000, oprez s ovim. Na kraju ponovno učitajte ExtraWatch backend.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_MAXID_BOTS', "Koliko posjeta botova sačuvati u bazi podataka.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_MAXID_VISITORS', "Koliko stvarnih posjeta sačuvati u bazi podataka.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LIMIT_BOTS', "Količina vidljivih botova u backend-u.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LIMIT_VISITORS', "Količina stvarnih posjeta vidljivih u backend-u.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_VISITS', "Najveća količina znakova vidljivih u dugim naslovima i adresama.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_STATS', "Najveća količina znakova vidljiva u desnoj statističkoj ploči.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_STATS_KEEP_DAYS', "Količina dana za čuvanje statistike u bazi podataka, 0 = beskonačno.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TIMEZONE_OFFSET', "Ukoliko se nalazite u drukčijoj vremenskoj zoni od servera. (pozitivne ili negativne vrijednosti u satima)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_WEEK_OFFSET', "Tjedni pomak, vremenska oznaka/(3600*24*7) daje tjednu broj od 1.1.1970, ovaj pomak je ispravka kako bi polazilo od ponedjeljka ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_DAY_OFFSET', "Dnevni pomak, vremenska oznaka/(3600*24) daje danu broj od 1.1.1970, ovaj pomak je ispravka kako bi polazilo od 00:00 ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_HIDE_LOGO', "&lt;b&gt;(radi u PRO verzoji)&lt;/b&gt; Korištenje prazne 1x1px ikone u frontend-u");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IP_STATS', "Za omogućavanje statistike IP adresa. U nekim je državama čuvanje IP adrese u bazi podataka na duže vrijeme zakonom zabranjeno. Korištenje na vlastitu odgovornost.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HIDE_ADS', "Ova postavka skriva reklame u backend-u, ukoliko Vam zaista smetaju. Ako ih ostavite, podržavate daljnje razvijanje ovog alata. Hvala");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_ONCLICK', "Odznačite ukoliko želite vidjeti opis alata usmjerivanjem pokazivača umjesto klikom.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SERVER_URI_KEY', "Zadana vrijednost je 'REDIRECT_URL', sto je norma za prepisivanje url-a, može se postaviti 'SCRIPT_URL' ukoliko bilježi samo index.php");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_BLOCKING_MESSAGE', "Poruka vidljiva blokiranim korisnicima ili objašnjenje razloga blokiranja.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_WIDTH', "Širina opisa alata");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_HEIGHT', "Visina opisa alata");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TOOLTIP_URL', "Za vizualiziranje posjetiteljeve IP adrese, ovdje možete postaviti bilo koji URL. IP adresa {ip} bit će zamijenjena posjetiteljevom IP adresom. Npr. http://somewebsite.com/query?iplookup={ip}");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_URI', "Ovdje možete postaviti bilo koji URI za kojeg želite da bude izuzet iz statistike. Možete koristiti zamjenske znakove (* i ?). Npr.: /freel?n* ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_NAME', "Upisite naziv cilja. Ovaj naziv bit će prikazan u statistikama.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_URI_CONDITION', "Sve što je iza imena domene. Za http://www.codegravity.com/projects/ URI je: /projects/ (Primjer korištenja: &lt;b&gt;/projects*&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_GET_VAR', "GET varijabla je varijabla koju možete vidjeti u URL-u iza ? ili &amp;amp; znaka. Npr. http://www.codegravity.com/index.php?&lt;u&gt;name&lt;/u&gt;=peter&amp;amp;&lt;u&gt;surname&lt;/u&gt;=smith. Smijete koristiti i &lt;u&gt;*&lt;/u&gt; u ovom polju kako bi pretražili sve get vrijednosti. (Primjer korištenja: &lt;b&gt;n*me&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_GET_CONDITION', "Ovdje morate navesti podudarnost za vrijednost s prethodnog polja. (Primjer korištenja: &lt;b&gt;p?t*r&lt;/b&gt;) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_POST_VAR', "Slično ali ovdje se provjeravaju vrijednosti poslane obrascima. Ako imate obrazac koji ima polje &amp;lt;input type='text' name='&lt;u&gt;experiences&lt;/u&gt;' /&amp;gt;. (Primjer korištenja: &lt;b&gt;exper*ces&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_POST_CONDITION', "Podudarnost za vrijednost ovog POST polja. Npr. želimo provjeriti ako korisnik ima iskustva u javi. (Primjer korištenja: &lt;b&gt;*java*&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_TITLE_CONDITION', "Naziv stranice koja se mora podudarati. (Primjer korištenja: &lt;b&gt;*freelance programmers*&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_USERNAME_CONDITION', "Ime ulogiranog korisnika. (Primjer korištenja: &lt;b&gt;psmith*&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_IP_CONDITION', "IP adresa s koje korisnik pristupa: (Primjer korištenja: &lt;b&gt;201.9?.*.*&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_CAME_FROM_CONDITION', "URL s kojeg korisnik pristupa. (Primjer korištenja: &lt;b&gt;*www.google.*&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_REDIRECT', "Korisnik je preusmjeren na URL koji ste naveli. Veći prioritet od blokiranja: (Primjer korištenja: &lt;b&gt;http://www.codegravity.com/goaway.html&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_TRUNCATE_GOALS', "Koliko znakova odrezati u tablici ciljeva");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_NO_BACKLINK', "&lt;b&gt;(radi u PRO verziji)&lt;/b&gt; Povratna poveznica na codegravity.com, mozete onemogućiti ali mi bi radije da to ostavite. Hvala");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES', "Prikaži ukupne statistike država u frontend modulu. Ako je promijenjeno, ova će postavka biti na snazi nakon vremena postavljenog u CACHE_FRONTEND_ ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_FIRST', "Ukoliko želite zamijeniti redoslijed Posjeta/Država u frontend-u. Ako odznačite, Posjetitelj će se prikazivati prvi.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_NUM', "Broj država prikazanih u frontend-u");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS', "Prikaži posjetitelje države u frontend modulu. Ako je promijenjeno, ova će postavka biti na snazi nakon vremena postavljenog u CACHE_FRONTEND_");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_COUNTRIES', "Vrijeme u sekundama za spremanje u predmemoriju ukupnih država na frontend-u");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_VISITORS', "Vrijeme u sekundama za spremanje u predmemoriju posjetitelja na frontend-u");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TODAY', "Za prikazivanje posjetitelja na frontend-u za: danas. Ako je promijenjeno, ova će postavka biti na snazi nakon vremena postavljenog u CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_YESTERDAY', "Za prikazivanje posjetitelja na frontend-u za: jučer. Ako je promijenjeno, ova će postavka biti na snazi nakon vremena postavljenog u CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_THIS_WEEK', "Za prikazivanje posjetitelja na frontend-u za: ovaj tjedan. Ako je promijenjeno, ova će postavka biti na snazi nakon vremena postavljenog u CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_LAST_WEEK', "Za prikazivanje posjetitelja na frontend-u za: prošli tjedan. Ako je promijenjeno, ova će postavka biti na snazi nakon vremena postavljenog u CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_THIS_MONTH', "Za prikazivanje posjetitelja na frontend-u za: ovaj mjesec. Ako je promijenjeno, ova će postavka biti na snazi nakon vremena postavljenog u CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_LAST_MONTH', "Za prikazivanje posjetitelja na frontend-u za: prošli mjesec. Ako je promijenjeno, ova će postavka biti na snazi nakon vremena postavljenog u CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TOTAL', "Za prikazivanje ukupnog broja posjetitelja od ExtraWatch instalacije. Ako je promijenjeno, ova će postavka biti na snazi nakon vremena postavljenog u CACHE_FRONTEND_...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_LANGUAGE', "Datoteka jezika koja se koristi. Smještene su u /components/com_extrawatch/lang/. Ako želite napraviti novu datoteku jezika, prvo provjerite stranicu projekta, a ako je tamo nema, kopirajte i preimenujte sa english.php na pr. german.php i smjestite u ovu mapu. Tada prevedite sve vrijednosti sa desne strane.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS', "Ciljevi Vam omogućavaju da precizirate posebne parametre. Kad se ti parametri podudaraju, brojač ciljeva se uvećava. Ovim načinom možete provjeravati ako je korisnik posjetio određeni URL, odaslao određenu vrijednost, ima određeno korisničko ime ili stiže s određene adrese. Tim možete blokirati ili preusmjeriti korisnike na neki drugi URL.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_INSERT', "U svim poljima osim naziva možete koristiti * i ? kao zamjenske znakove. Npr: ?ear (podudarat će se: near, tear, ..),  p*r (podudarat će se: pr, peer, pear ..) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_BLOCK', "Podesiti na 1 ukoliko želite blokirati posjetitelja. Tada neće vidjeti sadržaj već samo obavijest da je blokiran - bez preusmjeravanja i njegova IP adresa je dodana u blokirane statistike (Primjer za korištenje: &lt;b&gt;1&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* new translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY_CONDITION', "Uvjet za državu");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY_INVERSED', "Suprotni uvjet za državu");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_GOALS_COUNTRY_CONDITION', "Dvoslovni kod države velikim slovima (Npr: &lt;b&gt;TH&lt;/b&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_INTERNAL', "Interno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_FROM', "Od");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_TO', "Za");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_ADD_TO_GOALS', "Dodaj ciljevima");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISITS_ADD_GOAL_COUNTRY', "Dodaj cilj za ovu državu");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_REPORT_BUG', "Prijavi grešku ili značajku");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_COUNTRY', "Država");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


/* translations 1.2.8b_12 */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_UPPERCASE', "Ukoliko želite imena država velikim slovima u frontend-u (Npr: GERMANY, UNITED KINGDOM umjesto Germany, United Kingdom)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_CACHE_FRONTEND_USERS', "Vrijeme u sekundama za spremanje u predmemoriju korisnika u frontend-u");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_VISITORS_TOTAL_INITIAL', "Početna vrijednost prikaza u Ukupno: na frontend-u. Korisno ako migrirate sa drugog statističkog alata. (Npr.: 20000). Vratiti na 0 ukoliko ne želite koristiti ovu mogućnost.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_IGNORE_USER', "Ignoriraj korisnike navedene u ovom tekstnom okviru. Jedan po liniji. (Npr.: myself {nova linija} mark_*) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_USERS_MOST', "Najviše aktivnih korisnika danas od ukupnog");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SPAMWORD_BANS_ENABLED', "Omogući blokiranje u odnosu na riječi iz spam liste ispod ?");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_SPAMWORD_LIST', "Najčešće spam riječi korištene od strane spam botova. Možete koristiti zamjenske znakove, (Npr.: ph?rmac*). Ako je postavka omogućena, ExtraWatch će provjeriti je li napadač poslao obrazac sa spam riječima (HTTP POST zahtjev) na Vašoj stranici. (Odnosi se na to ako je obrazac na stranici koja se temelji na Joomli - forum, komentari, ali je prilično učinkovita za blokiranje spam botova koji pokušavaju poslati svaki obrazac)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_ANTI_SPAM', "Anti-Spam");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_USER_LINK', "Poveznica na frontend korisničkom modulu - omogućava određivanje određenog URL-a koji je otvoren kad korisnik klikne na korisničko ime. Mora sadržavati niz podataka {korisnik}, koji ce biti zamijenjen stvarnim korisničkim imenom. (Npr. index.php?option=com_comprofiler&amp;task=userProfile&amp;user={user}) ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* translations 1.2.11b */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYPHRASE', "Ključni izrazi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HISTORY_MAX_VALUES', "Najveća moguća vrijednost u kartici povijesti (Primjer: &lt;i&gt;100&lt;/i&gt;)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_DESC_ONLY_LAST_URI', "U posjetama prikaži samo posljednju stranicu, ne sve");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HIDE_REPETITIVE_TITLE', "U posjetama sakrij imena stranica koja se ponavljaju u naslovima posjećenih stranica");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_HISTORY_MAX_DB_RECORDS', "Najveći mogući broj posjeta spremljenih u bazi podataka za prikaz povjesti posjetitelja. Oprezno s ovom postavkom, ako imate velik promet može jako brzo narasti. Uvijek provjerite koliko podataka sadrži tablica povijesti u Statusu");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_UNINSTALL_KEEP_DATA', "Sačuvaj tablice baze podataka pri deinstalaciji. Označite ovu opciju prije deinstalacije ako želite sačuvati podatke pri nadogradnji.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* email reports */
DEFINE('_EW_DESC_EMAIL_REPORTS_ENABLED', "Primat ćete elektroničku poštu noću sa izviješćem o prethodnom danu koju možete pročitati ujutro");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_REPORTS_ADDRESS', "Adresa elektroničke pošte na koju želite primati izviješća");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_PERCENT_HIGHER_THAN', "Uključi redove u izviješću samo ako je postotak veći od {vrijednosti}. Podesiti na 0 ako ne želite koristiti ovu mogućnost &lt;i&gt;(primjer: 5)&lt;/i&gt;");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_ONE_DAY_CHANGE_POSITIVE', "Uključi samo &lt;b&gt;pozitivne dnevne&lt;/b&gt; promjene vrijednosti u izviješćima veće od {vrijednost} postotka. Podesiti na 0 ako ne želite koristiti ovu mogućnost &lt;i&gt;(primjer: 5)&lt;/i&gt;");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_ONE_DAY_CHANGE_NEGATIVE', "Uključi samo &lt;b&gt;negativne dnevne&lt;/b&gt; promjene vrijednosti u izviješćima manje od {vrijednost} postotka. Podesiti na 0 ako ne želite koristiti ovu mogućnost &lt;i&gt;(primjer: -10)&lt;/i&gt;");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEVEN_DAY_CHANGE_POSITIVE', "Uključi samo &lt;b&gt;pozitivne sedmodnevne&lt;/b&gt; promjene vrijednosti u izviješćima veće od {vrijednost} postotka. Podesiti na 0 ako ne želite koristiti ovu mogućnost &lt;i&gt;(primjer: 2)&lt;/i&gt;");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEVEN_DAY_CHANGE_NEGATIVE', "Uključi samo &lt;b&gt;negativne sedmodnevne&lt;/b&gt; promjene vrijednosti u izviješćima manje od {vrijednost} postotka. Podesiti na 0 ako ne želite koristiti ovu mogućnost &lt;i&gt;(primjer: -13)&lt;/i&gt;");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_TWENTY_EIGHT_DAY_CHANGE_POSITIVE', "Uključi samo &lt;b&gt;pozitivne 28-dnevne&lt;/b&gt; promjene vrijednosti u izviješćima veće od {vrijednost} postotka. Podesiti na 0 ako ne želite koristiti ovu mogućnost &lt;i&gt;(primjer: 2)&lt;/i&gt;");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_TWENTY_EIGHT_DAY_CHANGE_NEGATIVE', "Uključi samo &lt;b&gt;negativne 28-dnevne&lt;/b&gt; promjene vrijednosti u izviješćima manje od {vrijednost} postotka. Podesiti na 0 ako ne želite koristiti ovu mogućnost &lt;i&gt;(primjer: -13)&lt;/i&gt;");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_DESC_FRONTEND_NOFOLLOW', "&lt;b&gt;(radi u PRO verziji)&lt;/b&gt; Omogućite ovu postavku ukoliko želite da poveznica loga ima atribut rel='nofollow' ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_NAME_TRUNCATE', "Najveći mogući broj znakova u nazivlju retka u elektroničkoj pošti. Promijenite ovo ukoliko je prozor Vašeg klijenta elektroničke pošte premalen");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_MENU_HISTORY', "Povijest");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_EMAILS', "Elektronička pošta");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_STATUS', "Status baze podataka");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_BLOCKED', "Anti-spam je blokirao ove IP adrese");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_HISTORY_VISITORS', "Povjest posjetitelja");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_SHOWING_ONLY', "Prikazuje samo %d posljednih zapisa.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                Za mijenjanje ove vrijednosti idite na postavke -&amp;gt; Povijest &amp;amp; Performanse -&amp;gt; HISTORY_MAX_DB_RECORDS . Pažljivo, ova postavka utječe na vrijeme učitavanja podataka ispod.  ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_BUG', "Prijavi grešku");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_FEATURE', "Zatraži značajku");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_VISITS_CAME_FROM_KEYWORDS', "Ključne riječi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_BLOCKING_UNBLOCK', "odblokiraj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEYPHRASE ', "Ključni izraz");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATUS_DATABASE_TABLE_NAME', "ime tablice");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_ROWS', "redovi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_DATA', "podatak");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE_TOTAL', "ukupno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_EMAIL_REPORTS', "Izviješća elektroničke pošte");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORT_GENERATED', "Generira jučerašnja filtrirana izviješća elektroničke pošte");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_VALUE_FILTERS', "Vrijednosti filtera e-pošte");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_VALUE', "vrijednost");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_PERCENT', "postotak");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_1DAY_CHANGE', "dnevna promjena");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_7DAY_CHANGE', "sedmodnevna promjena");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EMAIL_REPORTS_28DAY_CHANGE', "28-dnevna promjena ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_BLOCKED', "ExtraWatch je blokirao %d spam pregleda danas, ukupno: %d");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_ADDRESSES', "Blokirane IP adrese");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_SETTINGS', "Anti-Spam postavke");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRAFFIC_AJAX', "AJAX ažurira promet (osim mapa)");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_HISTORY_PREVIOUS', "prethodno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_NEXT', "iduće");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/** additional translation for 1.2.11 for countries in more rows */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_MAX_COLUMNS', "Broj stupaca država");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_MAX_ROWS', "Broj redaka država");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_NAMES', "Prikaži ime države ili ne");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_FRONTEND_COUNTRIES_FLAGS_FIRST', "Prikaži prvo zastave pa postotke");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

/* ExtraWatch 1.2.14 translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_GOALS_GET_INVERSED', "GET suprotni uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_POST_INVERSED', "POST suprotni uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_TITLE_INVERSED', "Naziv suprotni uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_USERNAME_INVERSED', "Korisničko ime suprotni uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_GOALS_CAME_FROM_INVERSED', "Dolazi iz suprotni uvjet");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATS_MAP', "Mapa posljednje posjete");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_ENTER_KEY', "Molimo unesite &lt;a href='http://www.ipinfodb.com/register.php' target='_blank'&gt;ipinfodb.com&lt;/a&gt; ključ za prikaz mape posljednje posjete:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_STORE_KEY', "spremi ključ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAP_INVALID_KEY', "Molimo unesite pravovaljani ipinfodb ključ koji ste dobili od: &lt;a href='http://www.ipinfodb.com/register.php' target='_blank'&gt;ipinfodb.com&lt;/a&gt;");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZEQUERY_BAD_REQUEST', "POGREŠAN ZAHTJEV: ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_VISIT_SUBMITED_FIELDS', "Poslana polja obrazaca:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_URL_PARAMETERS', "URL parametri:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_ADD_PAGE', " Dodaj stranicu kao cilj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_BLOCK_IP', " Blokiraj ovu IP adresu");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_SUBMITED_FROM_VARIABLE', " Dodaj varijablu poslanu obrascem kao cilj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_VISIT_URL_PARAMETER_GOAL', " Dodaj ovaj URL parametar kao cilj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_TREND_EMPTY', "Prazno");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_NOT_NUMBER', " POZOR: Vrijednost koju ste unijeli nije broj. ExtraWatch neće raditi kako treba!");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_EVALUATION_LEFT', "&amp;nbsp; Ovo je 15-dnevna probna verzija. Ostalo dana: &lt;b&gt;%d&lt;/b&gt;. Molimo kupite doživotnu &lt;a href='http://www.codegravity.com/donate/extrawatch/' target='_blank'&gt;ExtraWatch licencu za svoju domenu za ovu i nadolazeće verzije.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRIAL_VERSION_EXPIRED', " Vaša probna verzija je istekla. Molimo kupite ExtraWatch");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_CONFIG_LICENSE_ACTIVATED', "Licenca uspješno aktivirana. Hvala");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CONFIG_LICENCE_DONT_MATCH', "&lt;b&gt;Greška: ključ licence i Vaša domena ne odgovaraju.&lt;/b&gt;&lt;br/&gt;Jeste li unijeli isto ime domene u obrazac kao što se vidi ispod? &lt;br/&gt;Click '&lt;b&gt;zatražite točan aktivacijski ključ&lt;/b&gt;' ispod, ili kontaktirajte: support@codegravity.com&lt;br/&gt;");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_VIEW_ADMINBODY_LONG_MESSAGE', "Ako predugo vidite poruku iznad, možda je vasa aktivna stranica kriva.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    Otvorite components/com_extrawatch/config.php  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    maknite komentare i postavite svoju pravu aktivnu stranicu. Npr.:  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    define('EXTRAWATCH_LIVE_SITE', 'http://www.codegravity.com');");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_ADMINBODY_LIVE_SITE', "Pozor: stranica u Vašem pregledniku i aktivna stranica u konfiguraciji: %s i %s se ne podudaraju.");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINBODY_SET_LIVE_SITE', "Podesite aktivnu stranicu na: %s i nastavite...");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_ADMINHEADER_JW', "ExtraWatch");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_REMOVE_BACKLINK', "Obriši povratnu poveznicu");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_KNOWLEDGE_BASE', "Baza znanja");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_FLOW', "Tijek");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_GRAPHS', "Grafovi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_COMPONENTS', "Komponente");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_REVIEW', "Osvrt");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_WRITE', "Napiši ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_FLOW_TRAFFIC', "Tijek prometa");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_SELECT_PAGE', "Označi stranicu:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_OUTG_LINKS', "Broj izvora odlazećih poveznica:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_NESTING', "Nivo gniježđenja:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FLOW_SCALE', "Razmjer:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_COMERCIAL_AD_FREE', "Verzija bez reklama");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_THANK_DONATION', "Puno Vam hvala na Vašoj donaciji!");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_REGISTRATION_KEY', "Registracijski ključ Vase domene %s je: ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_COMERCIAL_BACKLINKS_REMOVE', "Sad možete maknuti povratnu poveznicu ili sakriti ExtraWatch logo u frontend-u u Postavkama ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_SIZES_LAST_CHECK', "Posljednja provjera bila je:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_ADMINISTRATOR', "BLUE = Veličina component/module u /administrator direktoriju");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZECOMPONENTS_COMPONENT', "Komponenta");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_TOTAL', "Ukupno:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_SIZE', "Veličina");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZECOMPONENTS_REFRESH_ALL', "Osvježi sve");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZEDATABASE_TABLE', "Tablica");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_SIZE', "Veličina");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_1DAY', "Dnevna promjena");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_7DAY', "Sedmodnevna promjena");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_28DAY', "28-dnevna promjena");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_NO_DATA', "nema podataka");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_TOTAL', "Ukupno:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZEMODULES_REFRESH_ALL', "Osvježi sve");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_TOTAL', "Ukupno:");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_MODULE', "Modul");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEMODULES_SIZE', "Veličina");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_SIZES_FILES', "Datoteke &amp;amp; Direktoriji");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_BYTES', "bajtovi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_KB', "KB");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_MB', "MB");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_GB', "GB");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZES_REFRESH', "Osvježi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATS_FOOTER', "ExtraWatch &amp;copy;2006-%d by CodeGravity.com");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_STATUS_MB', "MB");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATUS_DATABASE', "Veličina tablica baze podataka");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


DEFINE('_EW_DESC_IPINFODB_KEY', "Mapa posljednje posjete ipinfodb.com ključ: &lt;a href='http://www.ipinfodb.com/register.php' target='_blank'&gt;ipinfodb.com&lt;/a&gt;");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SETTINGS_FORCE_TIMEZONE_OFFSET', "Prisili pomak vremenske zone");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


/* ExtraWatch 1.2.17 translations */  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_UPDATE', "Ažuriraj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MENU_UPDATE_TITLE', "Sigurnosna kopija &amp; Nadogradnja");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ADMINHEADER_NA_IN_THIS_VERSION', "Nije omogućeno u besplatnim verzijama, molimo pogledajte karticu Licenca");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SPAMWORD_BANS_ENABLED', "Omogući blokiranja sa spam riječima");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SPAMWORD_LIST', "Lista spam riječi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HIDE_REPETITIVE_TITLE', "Sakrij repetitivni naslov");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_VISITS', "Odsijeci posjete");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_STATS', "Odsijeci statistike");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TRUNCATE_GOALS', "Odsijeci ciljeve");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LIMIT_BOTS', "Ograniči botove");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_LIMIT_VISITORS', "Ograniči posjete");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_WIDTH', "Širina opisa alata");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_HEIGHT', "Visina opisa alata");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_URL', "URL opisa alata");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_TOOLTIP_ONCLICK', "Opis alata OnClick");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IP_STATS', "IP statistike");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IPINFODB_KEY', "IP Informacijski ključ baze podataka ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ONLY_LAST_URI', "Samo posljednji URI ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_FRONTEND_HIDE_LOGO', "Frontend sakrij logo ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_NOFOLLOW', "Frontend ne prati");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_NO_BACKLINK', "Frontend bez povratne poveznice");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_USER_LINK', "Korisnikove poveznice");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_FIRST', "Frontend države prve");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_NAMES', "Frontend imena država");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_UPPERCASE', "Frontend države velikim slovima");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_FLAGS_FIRST', "Frontend zastave država prve");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_NUM', "Frontend brojevi država");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_MAX_COLUMNS', "Frontend najveći mogući broj stupaca država");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_COUNTRIES_MAX_ROWS', "Frontend najveći mogući broj redaka država");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TODAY', "Frontend podjetitelji danas ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_YESTERDAY', "Frontend posjetitelji jučer ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_THIS_WEEK', "Frontend posjetitelji ovaj tjedan ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_LAST_WEEK', "Frontend posjetitelji prošli tjedan ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_FRONTEND_VISITORS_THIS_MONTH', "Frontend posjetitelji ovaj mjesec ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_LAST_MONTH', "Frontend posjetitelji prošli mjesec ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL', "Frontend sakrij ukupan broj posjetitelja");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL_INITIAL	', "Frontend početni broj ukupnog");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_MAX_VALUES', "Najveće vrijednosti povijesti");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_HISTORY_MAX_DB_RECORDS', "Najviše zapisa povijesti");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_UPDATE_TIME_VISITS', "Ažuriraj vrijeme posjete");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_UPDATE_TIME_STATS', "Ažuriraj vrijeme statistike");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_MAX_ROWS', "Statistike najviše redaka");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_IP_HITS', "Statistike IP pregledi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MAXID_BOTS', "Najviše ID botova");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_MAXID_VISITORS', "Najviše ID posjeta");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_STATS_KEEP_DAYS', "Koliko se dana čuvaju statistike ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CACHE_FRONTEND_COUNTRIES', "Spremi frontend države u predmemoriju ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_CACHE_FRONTEND_VISITORS', "Spremi frontend posjete u predmemoriju ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_UNINSTALL_KEEP_DATA	', "Sačuvaj podatke pri deinstalaciji ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_IP', "Ignoriraj IP");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_URI', "Ignoriraj URI");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_IGNORE_USER', "Ignoriraj korisnika");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_BLOCKING_MESSAGE', "Poruka za blokirane");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SERVER_URI_KEY', "Serverski URI ključ");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_FRONTEND_VISITORS_TOTAL_INITIAL', "Frontend početni broj ukupnih posjeta");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_SIZEDATABASE_RECORDS', "Zapisi");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
/***********EDITs*****************/  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_ANTISPAM_BLOCKING_TEXT', " Kako bi blokiranje bilo omogućeno morate objaviti ExtraWatch agenta PRIJE sadržaja ili obrazaca. Pr. na lijevoj strani predloška.  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    &lt;br/&gt;  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
                    Otiđite na Module Manager -&gt; ExtraWatch agent -&gt; označite lijevi položaj");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  

DEFINE('_EW_EMAIL_SEO_REPORTS', "SEO izviješća");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_DESC_EMAIL_SEO_REPORTS_ENABLED', "SEO noćna izviješća elektroničkom poštom omogućena");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  
DEFINE('_EW_WATCH_INSTALLATION_DEMO', "Pogledajte demo instalacije");  	 	    	    		  	 	  	 	  		 	 		    	 			 	   		  	 	 		 	 	   	      	  	 		 		 				 			 		  		    	 		 		  


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
