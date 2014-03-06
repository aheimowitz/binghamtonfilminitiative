var Domains = new Class({
    Implements:[Options],
    options:{
        id:'',
        domains:[],
        strings:{}
    },
    elements:{},
    initialize:function(options){        
        var self = this;
        self.setOptions(options);
        // identify elements for this field
        self.elements['field']=document.id(self.options.id);
        self.elements['domain']=document.id(self.options.id+'-domain');
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
        if(!self.validdomain(self.trim(domain)) || self.trim(domain).length == 0){
            alert(self.options.strings.INVALID);            
        } else {
            if(self.options.domains.contains(domain)){
                alert(self.options.strings.DUPLICATE);
            } else {
                self.options.domains[self.options.domains.length] = self.trim(domain);
                self.elements.domain.value = '';
                self.options.domains.sort();
                self.store();
            }
        }
    },
    edit:function(button){
        var self = this;
        self.elements.domain.value = self.getdomain(button);
        self.remove(button);
    },
    remove:function(button){   
        var self = this;
        self.options.domains = self.options.domains.erase(self.getdomain(button));
        self.store();
    },
    store:function(){       
        var self = this;
        self.elements.field.value = JSON.encode(self.options.domains).toBase64();
        self.clearlist();
        self.makelist();
    },
    clearlist:function(){
        var self = this;
        self.elements.list.getChildren('li').each(function(el){
            el.destroy();
        });
    },
    makelist:function(){
        var self = this;
        self.options.domains.each(function(domain){
            var listitem = new Element('li',{styles:{display:'block',clear:'both'}}).inject(self.elements.list,'bottom');
            var edit = new Element('button',{html:self.options.strings.EDIT}).inject(listitem,'bottom');
            var remove = new Element('button',{html:self.options.strings.REMOVE}).inject(listitem,'bottom');
            var text = new Element('span',{html:domain,style:'margin-left:10px;'}).inject(listitem,'bottom');
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
    getdomain:function(button){
        var parent = button.getParent('li');
        var domainspan = parent.getChildren('span');
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
})