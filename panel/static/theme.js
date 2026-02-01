(function(){
  'use strict';

  var KEY = 'realm_theme';
  var THEMES = {
    aurora: { name: 'Aurora（新版）', themeColor: '#F5F5F7' },
    classic: { name: 'Classic（旧版）', themeColor: '#0B0F14' }
  };

  function _get(){
    try{
      var t = localStorage.getItem(KEY);
      if(t && THEMES[t]) return t;
    }catch(_e){}
    // Default: show the new design first
    return 'aurora';
  }

  function _setMetaThemeColor(hex){
    try{
      var m = document.querySelector('meta[name="theme-color"]');
      if(!m) return;
      m.setAttribute('content', String(hex || ''));
    }catch(_e){}
  }

  function apply(theme){
    var t = (theme && THEMES[theme]) ? theme : _get();
    try{ document.documentElement.setAttribute('data-theme', t); }catch(_e){}
    _setMetaThemeColor(THEMES[t].themeColor);

    // Highlight active selection in menus
    try{
      var btns = document.querySelectorAll('[data-theme-set]');
      btns.forEach(function(b){
        var k = String(b.getAttribute('data-theme-set') || '');
        if(k === t) b.classList.add('active');
        else b.classList.remove('active');
      });
    }catch(_e){}
  }

  function set(theme){
    var t = (theme && THEMES[theme]) ? theme : 'aurora';
    try{ localStorage.setItem(KEY, t); }catch(_e){}
    apply(t);
  }

  function bind(){
    try{
      document.addEventListener('click', function(e){
        var el = e.target && e.target.closest ? e.target.closest('[data-theme-set]') : null;
        if(!el) return;
        e.preventDefault();
        var t = String(el.getAttribute('data-theme-set') || '');
        if(!THEMES[t]) return;
        set(t);
      });
    }catch(_e){}
  }

  // Init early + after DOM
  apply(_get());
  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', function(){ apply(_get()); bind(); });
  }else{
    bind();
  }

  window.Theme = { get:_get, set:set, apply:apply, THEMES:THEMES };
})();
