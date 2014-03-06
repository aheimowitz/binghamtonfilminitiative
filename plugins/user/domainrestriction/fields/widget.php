<?php
/**
 * @copyright	Copyright (C) 2005 - 2012 Michael Richey. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('JPATH_BASE') or die;

class JFormFieldWidget extends JFormField
{
	protected $type = 'Widget';

	protected function getInput()
	{            
            $html=array();
            $html[]='<ul>';
            $html[]='<li><label> </label>';
            $html[]='<fieldset class="radio">';
            $html[]='<button id="'.$this->id.'">'.JText::_('PLG_USER_DOMAINRESTRICTION_ADD').'</button>';
            $html[]='</fieldset>';
            $html[]='</li></ul>';
            return implode("\n",$html);
        }
        protected function getLabel() {
            return '';
        }
}