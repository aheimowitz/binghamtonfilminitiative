var AutoGroups = new Class({
    Implements:[Options],
    options:{
        id:'',
        autogroups:[],
        strings:{}
    },
    elements:{},
    initialize:function(options){        
        var self = this;
        self.setOptions(options);
        // identify elements for this field
        self.elements['field']=document.id(self.options.id);
        self.elements['domain']=document.id(self.options.id+'-domain');
        self.elements['groups']=document.id(self.options.id+'-groups');
        self.elements['save']=document.id(self.options.id+'-save');
        self.elements['list']=document.id(self.options.id+'-list');
        
        self.elements.save.addEvent('click',function(){
            self.add();
            return false;
        });
        
        self.makelist();
    },
    add:function(){       
        var self = this;
        var domain = self.elements.domain.value;
        var groups = [];
        self.elements.groups.getSelected().each(function(el){
            groups[groups.length]=el.value;
        });
        if(
            !self.validdomain(self.trim(domain)) || 
            self.trim(domain).length == 0 ||
            groups.length == 0
        ){
            alert(self.options.strings.INVALID);            
        } else {
            if(self.detectdupe(domain)){
                alert(self.options.strings.DUPLICATE);
            } else {
                self.options.autogroups[self.options.autogroups.length] = {domain:domain,groups:groups};
                self.elements.domain.value = '';
                self.elements.groups.getSelected().each(function(el){el.selected = false});
                if(self.elements.groups.hasClass('chzn-done')) {
                    // stupid jquery garbage
                    jQuery('#'+self.options.id+'-groups').trigger("liszt:updated");
                }
                self.options.autogroups.sortOn('domain',Array.CASEINSENSITIVE);
                self.store();
            }
        }
    },
    edit:function(button){
        var self = this;
        var domain = self.getdomain(button);
        var groups = [];
        self.elements.domain.value = domain;
        self.options.autogroups.each(function(autogroup){
            if(autogroup.domain == domain) {
                groups = autogroup.groups;
            }
        });
        self.elements.groups.getChildren().each(function(el){
            if(groups.contains(el.value)) el.selected = true;
        });
        if(self.elements.groups.hasClass('chzn-done')) {
            // stupid jquery garbage
            jQuery('#'+self.options.id+'-groups').trigger("liszt:updated");
        }        
        self.remove(button);
    },
    remove:function(button){   
        var self = this;
        var domain = self.getdomain(button);
        self.options.autogroups.each(function(autogroup,index){
            if(autogroup.domain == domain) {
                self.options.autogroups.splice(index,1);
            }
        })
        self.store();
    },
    store:function(){       
        var self = this;
        self.elements.field.value = JSON.encode(self.options.autogroups).toBase64();
        self.clearlist();
        self.makelist();
    },
    detectdupe:function(domain){
        var self = this;
        var domains = [];
        self.options.autogroups.each(function(autogroup){
            domains[domains.length]=autogroup.domain;
        });
        if(domains.contains(domain)){
            return true;
        } else {
            return false;
        }
    },
    clearlist:function(){
        var self = this;
        self.elements.list.getChildren('li').each(function(el){
            el.destroy();
        });
    },
    makelist:function(){
        var self = this;
        self.options.autogroups.each(function(autogroup){
            var listitem = new Element('li',{styles:{display:'block',clear:'both'}}).inject(self.elements.list,'bottom');
            var edit = new Element('button',{html:self.options.strings.EDIT}).inject(listitem,'bottom');
            var remove = new Element('button',{html:self.options.strings.REMOVE}).inject(listitem,'bottom');
            var text = new Element('span',{html:autogroup.domain,class:'domain',style:'margin-left:10px;'}).inject(listitem,'bottom');
            var grouptext = new Element('span',{html:'['+self.printgroups(autogroup.groups)+']',class:'groups',style:'margin-left:10px;'}).inject(listitem,'bottom');
            edit.addEvent('click',function(){
                self.edit(this);
                return false;
            });
            remove.addEvent('click',function(){
                self.remove(this);
                return false;
            });
        });
    },
    printgroups:function(groups) {
        var self = this;
        var printgroups = [];
        self.elements.groups.getChildren().each(function(el){
            if(groups.contains(el.value)) printgroups[printgroups.length]=el.get('html').replace(/^([-=\s]*)([a-zA-Z0-9])/gm,"$2");
        });
        return printgroups.join(', ');
    },
    getdomain:function(button){
        var parent = button.getParent('li');
        var domainspan = parent.getChildren('span.domain');
        var domain = domainspan.get('html')[0]; 
        return domain;
    },
    validdomain:function(domain){
        // not really sure if this is possible - more of a placeholder for the 
        // day I figure it out.
        return true;
    },
    trim:function(value){
        return value.replace(/^\s+|\s+$/g,'');
    }
});