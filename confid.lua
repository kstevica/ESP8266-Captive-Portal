gpio.mode(4, gpio.OUTPUT)
gpio.write(4, gpio.LOW)
clientactive = false
clientdns = false
counter = 0
usefile = ""

createap = function()
    wifi.setmode(wifi.SOFTAP)
    wifi.ap.config({ssid="open_internet",pwd=nil})
    srv=net.createServer(net.TCP) 
    srv:listen(80,function(conn) 
        conn:on("receive", function(client,request)
            local current = tmr.time()
            while clientactive do
                if tmr.time()-current>2 then
                    clientactive = false
                end
            end
            counter = counter + 1

            clientactive = true
            gpio.write(4, gpio.HIGH)
            local _, _, method, path, vars = string.find(request, "([A-Z]+) (.+)?(.+) HTTP");
            if(method == nil)then 
                _, _, method, path = string.find(request, "([A-Z]+) (.+) HTTP"); 
            end
            local _GET = {}
            if (vars ~= nil)then 
                for k, v in string.gmatch(vars, "(%w+)=(%w+)&*") do 
                    _GET[k] = v 
                end 
            end                
            if _GET.file == nil then       
                _GET.file = "web.html"
                _GET.type = "html"   
            end  
            usefile = _GET.file
            print ("FILE: ".._GET.file)                
            local header = "HTTP/1.1 200 OK\r\nContent-Type: text/".._GET.type.."\r\n\r\n"
            client:send(header)

            
            file.open(_GET.file, "r")
            local linesize = 1024
            local linedata = file.read(linesize)
            local linecounter = 0
            while linedata ~= nil do
                client:send(linedata)
                linecounter = linecounter + 1
                file.seek("set", linesize*linecounter)
                linedata = file.read(linesize)     
                print("Linecounter: ", linecounter)
                tmr.delay(10000)
            end                
            file.close()

            collectgarbage()
            if _GET.type == "html" then
                local secs = tmr.now()/1000000
                local minutes = secs / 60
                client:send("<br /><strong>This gadget has served "..counter.." pages since reboot. Free RAM: "..node.heap().." bytes, uptime: "..minutes.." minutes and "..(secs-minutes*60).." seconds. Serving ".._GET.file..".</strong>")
            end
            tmr.delay(1000000)
            client:close()
            gpio.write(4, gpio.LOW)
            clientactive = false
            
            linedata = nil
            collectgarbage()
            --print ("Free: ", node.heap())
        end)
    end)

end

function unhex(str)
    str = string.gsub (str, "(%x%x) ?",
        function(h) return string.char(tonumber(h,16)) end)
    return str
end

s=net.createServer(net.UDP)
    s:on("receive",function(s,c) 
        local transaction_id=string.sub(c,1,2)
        local flags=string.sub(c,3,4)
        local questions=string.sub(c,5,6)

        local query = ""
        local raw_query = ""
        local j=13
        while true do
            local byte = string.sub(c,j,j)
            j=j+1
            raw_query = raw_query .. byte
            if byte:byte(1)==0x00 then 
                break
            end
            for i=1,byte:byte(1) do
                byte = string.sub(c,j,j)
                j=j+1
                raw_query = raw_query .. byte
                query = query .. byte
            end
            query = query .. '.'
        end
        query=query:sub(1,query:len()-1) 
        local q_type = string.sub(c,j,j+1)
        j=j+2
        if q_type == unhex("00 01") then 
            local class = string.sub(c,j,j+1)

            local ip=unhex("C0 A8 04 01")
            local answers = unhex("00 01")
            flags = unhex("81 80")

            local resp=transaction_id..flags..questions..answers..unhex("00 00")..unhex("00 00")..raw_query..q_type..class
            resp=resp..unhex("c0 0c")..q_type..class..unhex("00 00 00 da")..unhex("00 04")..ip
            s:send(resp)
            collectgarbage()
            print("DNS, free:", node.heap())            
        end        
        collectgarbage()
    end) 
    s:listen(53)

createap()

print("listening, free:", node.heap())