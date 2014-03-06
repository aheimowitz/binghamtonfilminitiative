<?php
/**
 * @copyright	Copyright (C) 2005 - 2012 Michael Richey. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('JPATH_BASE') or die;

class JFormFieldButtons extends JFormField
{
	protected $type = 'Buttons';

	protected function getInput()
	{            
            $html=array();
            $html[]='<ul>';
            $html[]='<li><label> </label>';
            $html[]='<fieldset class="radio">';
            $html[]='<button id="'.$this->id.'">'.JText::_('PLG_USER_DOMAINRESTRICTION_EDIT').'</button>';
            $html[]='<button id="'.$this->id.'">'.JText::_('PLG_USER_DOMAINRESTRICTION_REMOVE').'</button>';
            $html[]='</fieldset>';
            $html[]='</li></ul>';
            return implode("\n",$html);
        }
        protected function getLabel() {
            return '';
        }
}