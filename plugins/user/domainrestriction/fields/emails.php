<?php
/**
 * @copyright	Copyright (C) 2005 - 2012 Michael Richey. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('JPATH_BASE') or die;

class JFormFieldEmails extends JFormField
{
	protected $type = 'Emails';

	protected function getInput()
	{
            JHtml::_('behavior.framework',true);
            $doc = JFactory::getDocument();
            $doc->addScript(JURI::root(true).'/media/plg_user_domainrestriction/js/emails.js');
            $doc->addScript(JURI::root(true).'/media/plg_user_domainrestriction/js/base64.js');
            $strings=array();
            foreach(array('ADD','EDIT','REMOVE','INVALID','DUPLICATE') as $string) {
                $strings[$string]=JText::_('PLG_USER_DOMAINRESTRICTION_'.$string);
            }
            $value = base64_decode($this->value)?trim(base64_decode($this->value)):json_encode(explode("\n",trim($this->value)));
            $script=array("window.addEvent('domready',function(){");
            $script[]="var ".$this->id.'_emailsobject = new Emails({';
            $script[]=implode(',',array("id:\"".$this->id."\"","emails:".$value,"strings:".json_encode($strings)));
            $script[]="})";
            $script[]='});';
            $doc->addScriptDeclaration(implode('',$script)."\n");
            $html=array();
            $html[]='<input type="text" id="'.$this->id.'-email" />';
            $html[]='<button id="'.$this->id.'-save">'.JText::_('PLG_USER_DOMAINRESTRICTION_ADD').'</button>';
            $html[]='<input id="'.$this->id.'" name="'.$this->name.'" type="hidden" value="'.base64_encode($value).'"/>';
            $html[]='<br style="clear:both" />';
            $html[]='<ul id="'.$this->id.'-list">';
            $html[]='</ul>';
            $html[]='<hr style="clear:both" />';
            return implode("\n",$html);
        }
}