<?php

/**
 * @copyright	Copyright (C) 2005 - 2011 Michael Richey. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

jimport('joomla.plugin.plugin');

class plgUserDomainRestriction extends JPlugin {

    public $_tlds;
    public $_domains;
    public $_emails;
    public $_badtlds;
    public $_baddomains;
    public $_bademails;
    public $_email;
    public $_domain;
    public $_tld;
    public $_allowed;

    public function onUserBeforeSave($user, $isnew, $new) {
        // are we manipulating a new user from the site?
        if (!$isnew || JFactory::getApplication()->isAdmin())
            return;
        
        $result = true;
        
        // retrieve and clean up domain and email params
        $this->_sortParams();
        $this->_parseEmail($new['email']);

        $this->_allowed = ($this->_tlds || $this->_domains || $this->_emails) ?
                ($this->_decision(true) ? true : false) : true;

        if ($this->_allowed &&
                ($this->_badtlds || $this->_baddomains || $this->_bademails)
        )
            $this->_allowed = $this->_decision(); // disallowed entries

        if (!$this->_allowed) {
            JFactory::getLanguage()->load('plg_user_domainrestriction', JPATH_ADMINISTRATOR);
            throw new Exception(JText::_('PLG_USER_DOMAINRESTRICTION_DENY'));
            $result = false;
        }
        return $result;
    }

    public function onUserAfterSave($user, $isnew, $success, $msg) {
        if ($isnew) 
            $this->_updateGroups($user);
        return true;
    }

    public function onUserLogin($user, $options) {
        $this->_updateGroups($user);
        return true;
    }

    private function _decision($allowed = false) {
        $ret = $allowed ?
                $this->_mailmatch(array('_tlds', '_domains', '_emails')) :
                !$this->_mailmatch(array('_badtlds', '_baddomains', '_bademails'));
        return $ret;
    }

    private function _mailmatch($keys = array()) {
        $ret = false;
        if ($this->$keys[0] || $this->$keys[1] || $this->$keys[2])
            if (in_array($this->_tld, $this->$keys[0]) || in_array($this->_domain, $this->$keys[1]) || in_array($this->_email, $this->$keys[2]))
                $ret = true;
        return $ret;
    }

    private function _sortParams() {
        foreach (array('_tld', '_domain', '_email', '_badtld', '_baddomain', '_bademail') as $param) {
            $paramvalue = $this->params->get(str_replace('_', '', $param), null);
            $arrayvar = $param . 's';
            $this->$arrayvar = array();
            $this->$arrayvar = json_decode(strtolower(base64_decode($paramvalue)));
            foreach ($this->$arrayvar as $key => $d)
                if (!strlen(trim($d))) 
                    unset($this->$arrayvar[$key]);
        }
    }

    private function _parseEmail($email) {
        $this->_email = strtolower($email);
        $email = explode('@', strtolower($email));
        $this->_domain = $email[1];
        $this->_tld = $this->_get_tld_from_url($email[1]);
        return $email;
    }

    private function _updateGroups($user) {
        // not functioning in administrator
        if (JFactory::getApplication()->isAdmin())
            return;

        // not functioning if there aren't any autogroups
        if (!strlen($this->params->get('autogroups', '')))
            return true;

        $db = JFactory::getDbo();
        $query = $db->getQuery(true);
        $query->select('id')->from('#__users')->where('username = ' . $db->quote($user['username']));
        $db->setQuery($query);
        $userid = $db->loadResult();
        $user = JFactory::getUser($userid);

        $excludegroups = $this->params->get('excludegroup', array());
        foreach ($user->groups as $group)
            if (in_array($group, (array) $excludegroups))
                return true;

        $email = $this->_parseEmail($user->email);
        $assignments = json_decode(base64_decode($this->params->get('autogroups', 'W10K')));
        if (!count($assignments))
            return true;

        foreach ($assignments as $key => $assignment) {
            if (is_array($assignment)) {
                $assignments[strtolower($assignment[0])] = $assignment[1];
            } else {
                $assignments[strtolower($assignment->domain)] = $assignment->groups;
            }
            unset($assignments[$key]);
        }
        $excluded = json_decode(base64_decode($this->params->get('excludeauto', 'W10K')));

        foreach ($excluded as $key => $exclude)
            $excluded[$key] = str_replace('*', $email[0], trim(strtolower($exclude)));

        if (in_array(strtolower($user->email), $excluded))
            return true;
        
        if (array_key_exists($this->_domain, $assignments) || array_key_exists($this->_tld, $assignments)) {
            $groupchange = false;
            $akey = array_key_exists($this->_domain, $assignments) ? $this->_domain : $this->_tld;
            foreach ($assignments[$akey] as $key => $groupid) {
                if (!in_array($groupid, $user->groups)) {
                    JUserHelper::addUserToGroup($user->id, $groupid);
                    $groupchange = true;
                }
            }
            foreach ($user->groups as $groupid) {
                if (!in_array($groupid, $assignments[$akey])) {
                    JUserHelper::removeUserFromGroup($user->id, $groupid);
                    $groupchange = true;
                }
            }
            if($groupchange) {
                $user->set('groups', JAccess::getGroupsByUser($user->id));
                $user->set('authlevels', JAccess::getAuthorisedViewLevels($user->id));
            }
        }
    }

    function _get_tld_from_url($url) {
        $url = strpos($url, '://') ? $url : 'http://' . $url;
        $host = parse_url($url);
        $domain = str_replace("__", "", $host['host']);
        $tail = strlen($domain) >= 7 ? substr($domain, -7) : $domain;
        $tld = strstr($tail, ".");
        return preg_replace('/^\./', '', $tld);
    }

}
