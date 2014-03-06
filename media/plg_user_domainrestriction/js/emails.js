var Emails = new Class({
    Implements:[Options],
    options:{
        id:'',
        emails:[],
        strings:{}
    },
    elements:{},
    initialize:function(options){        
        var self = this;
        self.setOptions(options);
        // identify elements for this field
        self.elements['field']=document.id(self.options.id);
        self.elements['email']=document.id(self.options.id+'-email');
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
        var email = self.elements.email.value;
        if(!self.validemail(self.trim(email)) || self.trim(email).length == 0){
            alert(self.options.strings.INVALID);            
        } else {
            if(self.options.emails.contains(email)){
                alert(self.options.strings.DUPLICATE);
            } else {
                self.options.emails[self.options.emails.length] = self.trim(email);
                self.elements.email.value = '';
                self.options.emails.sort();
                self.store();
            }
        }
    },
    edit:function(button){
        var self = this;
        self.elements.email.value = self.getemail(button);
        self.remove(button);
    },
    remove:function(button){   
        var self = this;
        self.options.emails = self.options.emails.erase(self.getemail(button));
        self.store();
    },
    store:function(){       
        var self = this;
        self.elements.field.value = JSON.encode(self.options.emails).toBase64();
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
        self.options.emails.each(function(email){
            var listitem = new Element('li',{styles:{display:'block',clear:'both'}}).inject(self.elements.list,'bottom');
            var edit = new Element('button',{html:self.options.strings.EDIT}).inject(listitem,'bottom');
            var remove = new Element('button',{html:self.options.strings.REMOVE}).inject(listitem,'bottom');
            var text = new Element('span',{html:email,style:'margin-left:10px;'}).inject(listitem,'bottom');
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
    getemail:function(button){
        var parent = button.getParent('li');
        var emailspan = parent.getChildren('span');
        var email = emailspan.get('html')[0]; 
        return email;
    },
    validemail:function(email){
        var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return re.test(email);
    },
    trim:function(value){
        return value.replace(/^\s+|\s+$/g,'');
    }
})