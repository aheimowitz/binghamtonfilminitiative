var TLDs = new Class({
    Implements:[Options],
    options:{
        id:'',
        tlds:[],
        strings:{}
    },
    elements:{},
    initialize:function(options){        
        var self = this;
        self.setOptions(options);
        // identify elements for this field
        self.elements['field']=document.id(self.options.id);
        self.elements['tld']=document.id(self.options.id+'-tld');
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
        var tld = self.elements.tld.value;
        if(!self.validtld(self.trim(tld)) || self.trim(tld).length == 0){
            alert(self.options.strings.INVALID);            
        } else {
            if(self.options.tlds.contains(tld)){
                alert(self.options.strings.DUPLICATE);
            } else {
                self.options.tlds[self.options.tlds.length] = self.trim(tld);
                self.elements.tld.value = '';
                self.options.tlds.sort();
                self.store();
            }
        }
    },
    edit:function(button){
        var self = this;
        self.elements.tld.value = self.gettld(button);
        self.remove(button);
    },
    remove:function(button){   
        var self = this;
        self.options.tlds = self.options.tlds.erase(self.gettld(button));
        self.store();
    },
    store:function(){       
        var self = this;
        self.elements.field.value = JSON.encode(self.options.tlds).toBase64();
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
        self.options.tlds.each(function(tld){
            var listitem = new Element('li',{styles:{display:'block',clear:'both'}}).inject(self.elements.list,'bottom');
            var edit = new Element('button',{html:self.options.strings.EDIT}).inject(listitem,'bottom');
            var remove = new Element('button',{html:self.options.strings.REMOVE}).inject(listitem,'bottom');
            var text = new Element('span',{html:tld,style:'margin-left:10px;'}).inject(listitem,'bottom');
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
    gettld:function(button){
        var parent = button.getParent('li');
        var tldspan = parent.getChildren('span');
        var tld = tldspan.get('html')[0]; 
        return tld;
    },
    validtld:function(tld){
        // not really sure if this is possible - more of a placeholder for the 
        // day I figure it out.
        return true;
    },
    trim:function(value){
        return value.replace(/^\s+|\s+$/g,'');
    }
})