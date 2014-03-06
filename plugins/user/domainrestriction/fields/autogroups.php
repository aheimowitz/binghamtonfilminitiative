<?php
/**
 * @copyright	Copyright (C) 2005 - 2012 Michael Richey. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('JPATH_BASE') or die;

class JFormFieldAutoGroups extends JFormField
{
	protected $type = 'AutoGroups';

	protected function getInput()
	{
            JHtml::_('behavior.framework',true);
            $doc = JFactory::getDocument();
            $doc->addScript(JURI::root(true).'/media/plg_user_domainrestriction/js/bulk.js');
            $doc->addScript(JURI::root(true).'/media/plg_user_domainrestriction/js/autogroups.js');
            $doc->addScript(JURI::root(true).'/media/plg_user_domainrestriction/js/base64.js');
            $doc->addScript(JURI::root(true).'/media/plg_user_domainrestriction/js/Array.sortOn.js');
            $strings=array();
            foreach(array('ADD','EDIT','REMOVE','INVALID','DUPLICATE') as $string) {
                $strings[$string]=JText::_('PLG_USER_DOMAINRESTRICTION_'.$string);
            }   
            // upgrading from a previous version of the plugin - this will convert the data
            $value = base64_decode($this->value);
            if(count(json_decode($value))){
                $value = json_decode($value);
                if(!is_object($value[0])) {
                    $newvalue = new stdClass;
                    foreach($value as $key=>$domain) {
                        $newvalue->domain=$domain[0];
                        $newvalue->groups=$domain[1];
                        $value[$key]=$newvalue;
                    }
                }
                $value = json_encode($value);
            }
            $script=array("window.addEvent('domready',function(){");
            $script[]="var ".$this->id.'_autogroupsobject = new AutoGroups({';
            $script[]=implode(',',array("id:\"".$this->id."\"","autogroups:".$value,"strings:".trim(json_encode($strings))));
            $script[]="})";
            $script[]='});';
            $doc->addScriptDeclaration(implode('',$script)."\n");
            $html=array();
            $html[]='<label for="'.$this->id.'-domain">'.JText::_('PLG_USER_DOMAINRESTRICTION_OPTIONS_DOMAIN_LABEL').'</label>';
            $html[]='<input type="text" id="'.$this->id.'-domain" />';
            $html[]='<label for="'.$this->id.'-groups">'.JText::_('PLG_USER_DOMAINRESTRICTION_OPTIONS_GROUPS_LABEL').'</label>';
            $html[]=JHtml::_('access.usergroup', $this->id.'-groups', '', 'multiple="multiple"', array()).'<br />';
            $html[]='<button id="'.$this->id.'-save">'.JText::_('PLG_USER_DOMAINRESTRICTION_ADD').'</button>';
            $html[]='<input id="'.$this->id.'" name="'.$this->name.'" type="hidden" value="'.base64_encode($value).'"/>';
            $html[]='<br style="clear:both" />';
            $html[]='<ul id="'.$this->id.'-list">';
            $html[]='</ul>';
            $html[]='<hr style="clear:both" />';
            return implode("\n",$html);
        }
}