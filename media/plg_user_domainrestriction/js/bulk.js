

var Bulk = new Class({
    initialize:function(){
        var self = this;
        $$('.bulk').each(function(el){
            el.addEvents({
//                keyup:function(){
//                    self.importvalues(this);
//                },
                change:function(){
                    self.importvalues(this);
                },
                paste:function(){
                    self.importvalues(this);
                }
            })
        })
    },
    importvalues:function(bulk){
        if(!bulk.value.length) return;
        bulkprefix = bulk.id.replace('bulk','').replace('jform_params_','');
        bulkprefix = bulkprefix.length?bulkprefix:'';
        typeset = document.id(bulk.id+'type');
        type=false;
        typeset.getChildren('input').each(function(el){
            if(el.checked) type=el.value;
        })
        if(!type) return;
        destination = document.id('jform_params_'+bulkprefix+type+'-'+type);
        button = document.id('jform_params_'+bulkprefix+type+'-save');        
        var entries = bulk.value.split("\n");
        Array.each(entries,function(entry){
            destination.value = entry;
            button.fireEvent('click');
        })
        bulk.value = '';
    }
})
window.addEvent('domready',function(){
    Object.append(Element.NativeEvents, {
        'paste': 2,
        'input': 2
    });

    Element.Events.paste = {
        base : (Browser.opera || (Browser.firefox && Browser.version < 2)) ? 'input': 'paste',
        condition: function(e) {
            this.fireEvent('paste', e, 1);
            return false;
        }
    };
    new Bulk();
})