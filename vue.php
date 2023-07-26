<script src="https://unpkg.com/vue@3"></script>
<div id="app">
	<h1>Hello ?name=${escapeHTML(name)}</h1>
</div>
<script>
  new Vue({
    el: '#app'
  });
</script>
