#!/bin/bash
shopt -s expand_aliases
Font_Black="\033[30m"
Font_Red="\033[31m"
Font_Green="\033[32m"
Font_Yellow="\033[33m"
Font_Blue="\033[34m"
Font_Purple="\033[35m"
Font_SkyBlue="\033[36m"
Font_White="\033[37m"
Font_Suffix="\033[0m"


parse_json() {
    local data="$1"
    local field="$2"
    # 增加对数据是否为空的检查
    [[ -z "$data" ]] && return
    
    if command -v jq &> /dev/null; then
        echo "$data" | jq -r ".$field" 2>/dev/null | xargs
    else
        # 改进的正则，支持更多字符类型
        echo "$data" | grep -oP "\"$field\":\s*\"?\K[^\",]+" | sed 's/\"//g' | head -1
    fi
}

while getopts ":I:M:EX:P:F:S:R:C:D:" optname; do
    case "$optname" in
        "I")
            iface="$OPTARG"
            useNIC="--interface $iface"
        ;;
        "M")
            if [[ "$OPTARG" == "4" ]]; then
                NetworkType=4
                elif [[ "$OPTARG" == "6" ]]; then
                NetworkType=6
            fi
        ;;
        "E")
            language="e"
        ;;
        "X")
            XIP="$OPTARG"
            xForward="--header X-Forwarded-For:$XIP"
        ;;
        "P")
            proxy="$OPTARG"
            usePROXY="-x $proxy"
        ;;
        "F")
            func="$OPTARG"
        ;;
        "S")
            Stype="$OPTARG"
        ;;
        "R")
            Resolve="$OPTARG"
            resolve="--resolve *:443:$Resolve"
        ;;
        "C")
            Curl="$OPTARG"
            alias curl=$Curl
        ;;
        "D")
            Dns="$OPTARG"
            dns="--dns-servers $Dns"
        ;;
        ":")
            echo "Unknown error while processing options"
            exit 1
        ;;
    esac
    
done

if [ -z "$iface" ]; then
    useNIC=""
fi

if [ -z "$XIP" ]; then
    xForward=""
fi

if [ -z "$proxy" ]; then
    usePROXY=""
fi

if [ -z "$Resolve" ]; then
    resolve=""
fi

if [ -z "$Dns" ]; then
    dns=""
fi

if ! mktemp -u --suffix=RRC &>/dev/null; then
    is_busybox=1
fi
curlArgs="$useNIC $usePROXY $xForward $resolve $dns --max-time 10"
UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.64"
UA_Dalvik="Dalvik/2.1.0 (Linux; U; Android 9; ALP-AL00 Build/HUAWEIALP-AL00)"
Media_Cookie=$(curl -s --retry 3 --max-time 10 "https://raw.githubusercontent.com/Memory2014/simpletest/refs/heads/main/cookies" &)
IATACode=$(curl -s --retry 3 --max-time 10 "https://raw.githubusercontent.com/Memory2014/simpletest/refs/heads/main/IATACode.txt" &)

checkOS() {
    ifTermux=$(echo $PWD | grep termux)
    ifMacOS=$(uname -a | grep Darwin)
    if [ -n "$ifTermux" ]; then
        os_version=Termux
        is_termux=1
        elif [ -n "$ifMacOS" ]; then
        os_version=MacOS
        is_macos=1
    else
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    fi
    
    if [[ "$os_version" == "2004" ]] || [[ "$os_version" == "10" ]] || [[ "$os_version" == "11" ]]; then
        is_windows=1
        ssll="-k --ciphers DEFAULT@SECLEVEL=1"
    fi
    
    if [ "$(which apt 2>/dev/null)" ]; then
        InstallMethod="apt"
        is_debian=1
        elif [ "$(which dnf 2>/dev/null)" ] || [ "$(which yum 2>/dev/null)" ]; then
        InstallMethod="yum"
        is_redhat=1
        elif [[ "$os_version" == "Termux" ]]; then
        InstallMethod="pkg"
        elif [[ "$os_version" == "MacOS" ]]; then
        InstallMethod="brew"
    fi
}
checkOS

checkCPU() {
    CPUArch=$(uname -m)
    if [[ "$CPUArch" == "aarch64" ]]; then
        arch=_arm64
        elif [[ "$CPUArch" == "i686" ]]; then
        arch=_i686
        elif [[ "$CPUArch" == "arm" ]]; then
        arch=_arm
        elif [[ "$CPUArch" == "x86_64" ]] && [ -n "$ifMacOS" ]; then
        arch=_darwin
    fi
}
checkCPU

checkDependencies() {
    
    # os_detail=$(cat /etc/os-release 2> /dev/null)
    
    if ! command -v python &>/dev/null; then
        if command -v python3 &>/dev/null; then
            alias python="python3"
        else
            if [ "$is_debian" == 1 ]; then
                echo -e "${Font_Green}Installing python3${Font_Suffix}"
                $InstallMethod update >/dev/null 2>&1
                $InstallMethod install python3 -y >/dev/null 2>&1
                alias python="python3"
                elif [ "$is_redhat" == 1 ]; then
                echo -e "${Font_Green}Installing python3${Font_Suffix}"
                if [[ "$os_version" -gt 7 ]]; then
                    $InstallMethod makecache >/dev/null 2>&1
                    $InstallMethod install python3 -y >/dev/null 2>&1
                    alias python="python3"
                else
                    $InstallMethod makecache >/dev/null 2>&1
                    $InstallMethod install python3 -y >/dev/null 2>&1
                fi
                
                elif [ "$is_termux" == 1 ]; then
                echo -e "${Font_Green}Installing python3${Font_Suffix}"
                $InstallMethod update -y >/dev/null 2>&1
                $InstallMethod install python3 -y >/dev/null 2>&1
                alias python="python3"
                
                elif [ "$is_macos" == 1 ]; then
                echo -e "${Font_Green}Installing python3${Font_Suffix}"
                $InstallMethod install python3
                alias python="python3"
            fi
        fi
    fi
    
    if ! command -v jq &>/dev/null; then
        if [ "$is_debian" == 1 ]; then
            echo -e "${Font_Green}Installing jq${Font_Suffix}"
            $InstallMethod update >/dev/null 2>&1
            $InstallMethod install jq -y >/dev/null 2>&1
            elif [ "$is_redhat" == 1 ]; then
            echo -e "${Font_Green}Installing jq${Font_Suffix}"
            $InstallMethod makecache >/dev/null 2>&1
            $InstallMethod install jq -y >/dev/null 2>&1
            elif [ "$is_termux" == 1 ]; then
            echo -e "${Font_Green}Installing jq${Font_Suffix}"
            $InstallMethod update -y >/dev/null 2>&1
            $InstallMethod install jq -y >/dev/null 2>&1
            elif [ "$is_macos" == 1 ]; then
            echo -e "${Font_Green}Installing jq${Font_Suffix}"
            $InstallMethod install jq
        fi
    fi
    
    if [ "$is_macos" == 1 ]; then
        if ! command -v md5sum &>/dev/null; then
            echo -e "${Font_Green}Installing md5sha1sum${Font_Suffix}"
            $InstallMethod install md5sha1sum
        fi
    fi
    
}
checkDependencies
if [ -z "$func" ]; then
    local_ipv4=$(curl $curlArgs -4 -s --max-time 10 cloudflare.com/cdn-cgi/trace | grep ip | awk -F= '{print $2}' &)
    local_ipv6=$(curl $curlArgs -6 -s --max-time 20 cloudflare.com/cdn-cgi/trace | grep ip | awk -F= '{print $2}' &)
    wait
    ripe_stat_v4=$(curl $curlArgs -s --max-time 10 "https://stat.ripe.net/data/prefix-overview/data.json?resource=$local_ipv4" &)
    ripe_stat_v6=$(curl $curlArgs -s --max-time 10 "https://stat.ripe.net/data/prefix-overview/data.json?resource=$local_ipv6" &)
    wait
    local_isp4=$(echo $ripe_stat_v4 | jq .data.asns[0].holder | tr -d '"')
    local_as4=$(echo $ripe_stat_v4 | jq .data.asns[0].asn | tr -d '"')
    local_ipv4_asterisk=$(echo $ripe_stat_v4 | jq .data.resource | tr -d '"')
    local_isp6=$(echo $ripe_stat_v6 | jq .data.asns[0].holder | tr -d '"')
    local_as6=$(echo $ripe_stat_v6 | jq .data.asns[0].asn | tr -d '"')
    local_ipv6_asterisk=$(echo $ripe_stat_v6 | jq .data.resource | tr -d '"')
    wait
fi


ShowRegion() {
    echo -e "${Font_Yellow} ---${1}---${Font_Suffix}"
}

function detect_isp() {
    local lan_ip=$(echo "$1" | grep -Eo "^(10\.[0-9]{1,3}\.[0-9]{1,3}\.((0\/([89]|1[0-9]|2[0-9]|3[012]))|([0-9]{1,3})))|(172\.(1[6789]|2\[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}(\/(1[6789]|2[0-9]|3[012]))?)|(192\.168\.[0-9]{1,3}\.[0-9]{1,3}(\/(1[6789]|2[0-9]|3[012]))?)$")
    if [ -n "$lan_ip" ]; then
        echo "LAN"
        return
    else
        local res=$(curl $curlArgs --user-agent "${UA_Browser}" -s --max-time 20 "https://api.ip.sb/geoip/$1" | jq ".isp" | tr -d '"' )
        echo "$res"
        return
    fi
}

function Test_Steam() {
    local result=$(curl $curlArgs --user-agent "${UA_Browser}" -${1} -fsSL --max-time 10 "https://store.steampowered.com/app/761830" 2>&1 | grep priceCurrency | cut -d '"' -f4)

    if [ ! -n "$result" ]; then
        echo -n -e "\r Steam Currency:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    else
        echo -n -e "\r Steam Currency:\t\t\t${Font_Green}${result}${Font_Suffix}\n"
    fi
}

function Test_Netflix() {
    local tmpresult1=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsL --max-time 10 --tlsv1.3 "https://www.netflix.com/title/81280792" 2>&1)
    local tmpresult2=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsL --max-time 10 --tlsv1.3 "https://www.netflix.com/title/70143836" 2>&1)
    if [[ "$tmpresult1" == "curl"* ]] || [[ "$tmpresult2" == "curl"* ]]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result1=$( echo "$tmpresult1" | grep "og:video" )
    local result2=$( echo "$tmpresult2" | grep "og:video" )
    local region1=$( echo -e $(echo "$tmpresult1" | grep 'netflix.reactContext' | awk -F= '{print $2}' | awk -F\; '{print $1}') | tr -d '[:cntrl:]' | sed 's/\^[^$]*\$//g' | jq '.models.geo.data.requestCountry.id' | tr -d '"' )

    if [ -n "$result1" ] || [ -n "$result2" ]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Green}Yes (Region: ${region1})${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Netflix:\t\t\t\t${Font_Yellow}Originals Only (Region: ${region1})${Font_Suffix}\n"
        return
    fi
    echo -n -e "\r Netflix:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
}

function Test_DisneyPlus() {
    local PreAssertion=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://disney.api.edge.bamgrid.com/devices" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -H "content-type: application/json; charset=UTF-8" -d '{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}' 2>&1)
    if [[ "$PreAssertion" == "curl"* ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed (Network Connection[1])${Font_Suffix}\n"
        return
    fi

    local assertion=$(echo $PreAssertion | python -m json.tool 2>/dev/null | grep assertion | cut -f4 -d'"')
    local PreDisneyCookie=$(echo "$Media_Cookie" | sed -n '1p')
    local disneycookie=$(echo $PreDisneyCookie | sed "s/DISNEYASSERTION/${assertion}/g")
    local TokenContent=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://disney.api.edge.bamgrid.com/token" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycookie" 2>&1)
    if [[ "$TokenContent" == "curl"* ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed (Network Connection[2])${Font_Suffix}\n"
        return
    fi
    local isBanned=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'forbidden-location')
    local is403=$(echo $TokenContent | grep '403 ERROR')

    if [ -n "$isBanned" ] || [ -n "$is403" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No (Banned)${Font_Suffix}\n"
        return
    fi

    local fakecontent=$(echo "$Media_Cookie" | sed -n '8p')
    local refreshToken=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'refresh_token' | awk '{print $2}' | cut -f2 -d'"')
    local disneycontent=$(echo $fakecontent | sed "s/ILOVEDISNEY/${refreshToken}/g")
    local tmpresult=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -X POST -sSL --max-time 10 "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql" -H "authorization: ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycontent" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed (Network Connection[3])${Font_Suffix}\n"
        return
    fi
    local previewchecktmp=$(curl $curlArgs -${1} -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.disneyplus.com")
    if [[ "$previewchecktmp" == "curl"* ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed (Network Connection[4])${Font_Suffix}\n"
        return
    fi
    local previewcheck=$(echo $previewchecktmp | grep preview)
    local isUnavailable=$(echo $previewcheck | grep 'unavailable')
    local region=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'countryCode' | cut -f4 -d'"')
    local inSupportedLocation=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'inSupportedLocation' | awk '{print $2}' | cut -f1 -d',')

    if [[ "$region" == "JP" ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Green}Yes (Region: JP)${Font_Suffix}\n"
        return
    elif [ -n "$region" ] && [[ "$inSupportedLocation" == "false" ]] && [ -z "$isUnavailable" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Yellow}Available For [Disney+ $region] Soon${Font_Suffix}\n"
        return
    elif [ -n "$region" ] && [ -n "$isUnavailable" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No (Unavailable)${Font_Suffix}\n"
        return
    elif [ -n "$region" ] && [[ "$inSupportedLocation" == "true" ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
        return
    elif [ -z "$region" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No (Unknown)${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

}

function Test_PeacockTV() {
    local tmpresult=$(curl $curlArgs -${1} -fsL -w "%{http_code}\n%{url_effective}\n" -o /dev/null "https://www.peacocktv.com/" 2>&1)
    if [[ "$tmpresult" == "000"* ]]; then
        echo -n -e "\r Peacock TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | grep 'unavailable')
    if [ -n "$result" ]; then
        echo -n -e "\r Peacock TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r Peacock TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    fi
}


function Test_YouTube_Premium() {
    local tmpresult1=$(curl $curlArgs --user-agent "${UA_Browser}" -${1} --max-time 10 -sSL -H "Accept-Language: en" -b "YSC=BiCUU3-5Gdk; CONSENT=YES+cb.20220301-11-p0.en+FX+700; GPS=1; VISITOR_INFO1_LIVE=4VwPMkB7W5A; PREF=tz=Asia.Shanghai; _gcl_au=1.1.1809531354.1646633279" "https://www.youtube.com/premium" 2>&1)
    local tmpresult2=$(curl $curlArgs --user-agent "${UA_Browser}" -${1} --max-time 10 -sSL -H "Accept-Language: en" "https://www.youtube.com/premium" 2>&1)
    local tmpresult="$tmpresult1:$tmpresult2"

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local isCN=$(echo $tmpresult | grep 'www.google.cn')
    if [ -n "$isCN" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix} ${Font_Green} (Region: CN)${Font_Suffix} \n"
        return
    fi

    local region=$(echo $tmpresult | grep "countryCode" | sed 's/.*"countryCode"//' | cut -f2 -d'"')
    local isAvailable=$(echo $tmpresult | grep 'purchaseButtonOverride')
    local isAvailable2=$(echo $tmpresult | grep "Start trial")

    if [ -n "$isAvailable" ] || [ -n "$isAvailable2" ] || [ -n "$region" ]; then
        if [ -n "$region" ]; then
            echo -n -e "\r YouTube Premium:\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
            return
        else
            echo -n -e "\r YouTube Premium:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
            return
        fi
    else
        if [ -n "$region" ]; then
            echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No  (Region: $region)${Font_Suffix} \n"
            return
        else
            echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix} \n"
            return
        fi
    fi
    echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}Failed${Font_Suffix}\n"

}

function Test_YouTube_CDNxxxx() {
    local tmpresult=$(curl $curlArgs -${1} -sS --max-time 10 "https://redirector.googlevideo.com/report_mapping?di=no" 2>&1)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r YouTube Region:\t\t\t${Font_Red}Check Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local cdn_node=$(echo $tmpresult | awk '{print $3}')
    if [[ "$cdn_node" == *"-"* ]]; then
        local CDN_ISP=$(echo $cdn_node | cut -f1 -d"-" | tr [:lower:] [:upper:])
        local CDN_LOC=$(echo $cdn_node | cut -f2 -d"-" | sed 's/[^a-z]//g')
        local lineNo=$(echo "${IATACode}" | cut -f3 -d"|" | sed -n "/${CDN_LOC^^}/=")
        local location=$(echo "${IATACode}" | awk "NR==${lineNo}" | cut -f1 -d"|" | sed -e 's/^[[:space:]]*//' | sed 's/\s*$//')
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Yellow}$CDN_ISP in $location ($cdn_node)${Font_Suffix}\n"
        return
    fi
    if [[ "$cdn_node" == *"s"* ]]; then
        local CDN_LOC=$(echo $cdn_node | cut -f2 -d"-" | cut -c1-3)
        local lineNo=$(echo "${IATACode}" | cut -f3 -d"|" | sed -n "/${CDN_LOC^^}/=")
        local location=$(echo "${IATACode}" | awk "NR==${lineNo}" | cut -f1 -d"|" | sed -e 's/^[[:space:]]*//' | sed 's/\s*$//')
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Green}$location ($cdn_node)${Font_Suffix}\n"
        return
    fi
    echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    return  
}


function Test_YouTube_CDN() {
    local ip_ver="${1:-4}"          # 默认 IPv4，可传 4 或 6
    local net_flag="-${ip_ver}"

    echo -n -e " YouTube CDN/Region (${ip_ver}):\t\t"

    # 你的 curl 参数（假设 $curlArgs 已定义，如 -4/-6 已包含在 net_flag 中）
    local tmpresult
    tmpresult=$($CURL_BIN ${net_flag} -sS --max-time 10 \
        ${useNIC} ${usePROXY} ${xForward} ${resolve} ${dns} \
        "https://redirector.googlevideo.com/report_mapping?di=no" 2>&1)

    if [[ "$tmpresult" == "curl"* || -z "$tmpresult" ]]; then
        echo -e "${Font_Red}Check Failed (Network / Timeout)${Font_Suffix}"
        return
    fi

    # 提取映射右侧部分（最常见格式：IP => node (subnet) 或只是 node）
    local mapping
    mapping=$(echo "$tmpresult" | grep -o '=>.*' | sed 's/^=> *//; s/ *(.*//')

    if [[ -z "$mapping" ]]; then
        # 有些响应只有一行 node，没有 =>
        mapping="$tmpresult"
    fi

    # 清理多余空格
    mapping=$(echo "$mapping" | tr -d '[:space:]')

    if [[ -z "$mapping" ]]; then
        echo -e "${Font_Red}Failed (Empty response)${Font_Suffix}"
        return
    fi

    # 尝试提取位置代码（兼容多种格式）
    local cdn_node="$mapping"
    local loc_code=""
    local isp_code=""

    # 经典 sn- 格式：r6---sn-abc123 → abc
    if [[ "$cdn_node" =~ sn-([a-z0-9]{3}) ]]; then
        loc_code="${BASH_REMATCH[1]}"
        isp_code="GOOGLE"
    # peering/ISP 格式：rjil-ixc1, edge-ord1, etc.
    elif [[ "$cdn_node" =~ ^([a-z]+)-([a-z0-9]+) ]]; then
        isp_code="${BASH_REMATCH[1]^^}"
        loc_code="${BASH_REMATCH[2]}"
    # 其他：rX-ord, etc.
    elif [[ "$cdn_node" =~ -([a-z]{3}) ]]; then
        loc_code="${BASH_REMATCH[1]}"
        isp_code="GOOGLE"
    fi

    # 转大写匹配 IATA
    loc_code="${loc_code^^}"

    if [[ -z "$loc_code" ]]; then
        echo -e "${Font_Yellow}Unknown format: $cdn_node${Font_Suffix}"
        return
    fi

    # 查找 IATA 对应行号（安全处理无匹配）
    local lineNo
    lineNo=$(echo "${IATACode}" | grep -i "^[^|]*|[^|]*|${loc_code}|" | head -1 | cut -f3 -d"|" | sed -n '/./=')

    if [[ -z "$lineNo" ]]; then
        # 无匹配 → 显示原始 node + 提示
        echo -e "${Font_Yellow}$cdn_node (location code $loc_code not in IATA list)${Font_Suffix}"
        return
    fi

    local location
    location=$(echo "${IATACode}" | awk -v nr="$lineNo" 'NR==nr {print $1}' FS="|" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    if [[ -z "$location" ]]; then
        location="???"
    fi

    if [[ -n "$isp_code" && "$isp_code" != "GOOGLE" ]]; then
        echo -e "${Font_Yellow}${isp_code} in ${location} (${cdn_node})${Font_Suffix}"
    else
        echo -e "${Font_Green}${location} (${cdn_node})${Font_Suffix}"
    fi
}

function Test_PrimeVideo_Region() {
    local tmpresult=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -sL --max-time 10 "https://www.primevideo.com" 2>&1)

    if [[ "$tmpresult" = "curl"* ]]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local tmpresult1=$(curl $curlArgs -${1} --user-agent "PrimeVideo/10.68 (iPad; iOS 18.3.2; Scale/2.00)" -sL --max-time 10 "https://ab9f7h23rcdn.eu.api.amazonvideo.com/cdp/appleedge/getDataByTransform/v1/apple/detail/vod/v1.kt?itemId=amzn1.dv.gti.e6b39984-2bb6-f7d0-33e4-08ec574947f0&deviceId=6F97F9CCFA2243F1A3C44BD3C7F7908E&deviceTypeId=A3JTVZS31ZJ340&density=2x&firmware=10.6800.16104.3&format=json&enabledFeatures=denarius.location.gen4.daric.siglos.siglosPartnerBilling.contentDescriptors.contentDescriptorsV2.productPlacement.zeno.seriesSearch.tapsV2.dateTimeLocalization.multiSourcedEvents.mseEventLevelOffers.liveWatchModal.lbv.daapi.maturityRatingDecoration.seasonTrailer.cleanSlate.xbdModalV2.xbdModalVdp.playbackPinV2.exploreTab.reactions.progBadging.atfEpTimeVis.prereleaseCx.vppaConsent.episodicRelease.movieVam.movieVamCatalog&journeyIngressContext=8%7CEgRzdm9k&osLocale=zh_Hans_CN&timeZoneId=Asia%2FShanghai&uxLocale=zh_CN" 2>&1)
    if [[ "$tmpresult1" = "curl"* ]]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local VPNDetected=$(echo $tmpresult1 | grep "您的设备使用了 VPN 或代理服务连接互联网请禁用并重试")

    local result=$(echo $tmpresult | grep '"currentTerritory":' | sed 's/.*currentTerritory//' | cut -f3 -d'"' | head -n 1)
    if [ -n "$result" ]; then
        if [ -n "$VPNDetected" ]; then
            echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}No  (VPN Detected;Region: $result)${Font_Suffix}\n"
            return
        else
            echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Green}Yes (Region: $result)${Font_Suffix}\n"
            return
        fi
    else
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Unsupported${Font_Suffix}\n"
        return
    fi

}

function Test_NetflixCDN() {
    #Detect Hijack
    if [[ "$1" == "6" ]]; then
        local nf_web_ip=$(getent ahostsv6 www.netflix.com | head -1 | awk '{print $1}')
    else
        local nf_web_ip=$(getent ahostsv4 www.netflix.com | head -1 | awk '{print $1}')
    fi
    if [ ! -n "$nf_web_ip" ]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Null${Font_Suffix}\n"
        return
    else
        local nf_web_isp=$(detect_isp $nf_web_ip)
        if [[ ! "$nf_web_isp" == *"Amazon"* ]] && [[ ! "$nf_web_isp" == *"Netflix"* ]]; then
            echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Yellow}Hijacked with [$nf_web_isp]${Font_Suffix}\n"
            return
        fi
    fi
    #Detect ISP's OCAs 
    local tmpresult=$(curl $curlArgs -${1} -sS --max-time 10 "https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=1" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local isp=$(echo $tmpresult | jq .client.isp)
    local target_city=$(echo $tmpresult | jq .targets[0].location.city | tr -d '"')
    local target_country=$(echo $tmpresult | jq .targets[0].location.country | tr -d '"')
    local isp=$(echo $tmpresult | jq .client.isp | tr -d '"')
    local target_url=$(echo $tmpresult | jq .targets[0].url | tr -d '"')
    local target_fqdn=$(echo $target_url |awk -F"/" '{print $3}'| awk -F"." '{print $1}')
    if [ -n "$isp" ] && [[ "${isp}" != "null" ]] && [[ $target_url == *"isp.1.oca"*  ]]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Yellow}${isp}'s OCAs in ${target_city},${target_country} ($target_fqdn)${Font_Suffix}\n"
        return
    fi
    if [[ $target_url == *"isp.1.oca"* ]]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Yellow}ISP's OCAs in ${target_city},${target_country} ($target_fqdn)${Font_Suffix}\n"
        return
    fi
    #Detect Offical OCAs
    if [ -n "$target_city" ] && [ -n "$target_city" ]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Green}${target_city},${target_country} ($target_fqdn)${Font_Suffix}\n"
        return
    fi
    echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    return      
}

function Test_HBO() {
    local mode="-${1}"  # "-4" 或 "-6" -${1}
    local mode_text="${2}"
    local curlArgs="${mode} -L --connect-timeout 10 -sS"
    
    if ! command -v jq &> /dev/null; then apt update && apt install jq -y || yum install jq -y; fi
    
    # 生成随机设备ID
    RAND_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "afbb5daa-c327-461d-9460-d8e4b3ee4a1f")
    #echo -e " HBO Max ${RAND_ID}"

    # 检查该协议栈是否可用
    if ! curl $mode -o /dev/null --connect-timeout 3 -s https://www.google.com; then
        echo -e " HBO Max:\t\t\t${Font_Yellow}Skipped (No $mode_text Connectivity)${Font_Suffix}"
        return
    fi
    
    local GetToken=$(curl $curlArgs "https://default.any-any.prd.api.hbomax.com/token?realm=bolt&deviceId=${RAND_ID}" \
    -H "x-device-info: beam/5.0.0 (desktop/desktop; Windows/10; ${RAND_ID}/${RAND_ID})" \
    -H 'x-disco-client: WEB:10:beam:5.2.1' 2>&1)

    if [[ "$GetToken" == "curl"* ]] || [[ -z "$GetToken" ]]; then
        echo -e " HBO Max:\t\t\t\t${Font_Red}Failed (Network Error)${Font_Suffix}"
        return
    fi

    local Token=$(echo $GetToken | jq -r .data.attributes.token 2>/dev/null)
    local APITemp=$(curl $curlArgs "https://default.any-any.prd.api.hbomax.com/session-context/headwaiter/v1/bootstrap" -X POST -H "Cookie: st=${Token}" 2>/dev/null)
    
    local domain=$(echo $APITemp | jq -r .routing.domain 2>/dev/null)
    local tenant=$(echo $APITemp | jq -r .routing.tenant 2>/dev/null)
    local env=$(echo $APITemp | jq -r .routing.env 2>/dev/null)
    local homeMarket=$(echo $APITemp | jq -r .routing.homeMarket 2>/dev/null)
    
    local tmpresult=$(curl $curlArgs "https://default.$tenant-$homeMarket.$env.$domain/users/me" -H "Cookie: st=${Token}" 2>/dev/null)
    local result=$(echo $tmpresult | jq -r .data.attributes.currentLocationTerritory 2>/dev/null)
    local availableRegion=$(curl $curlArgs -SL "https://www.hbomax.com/" 2>/dev/null | grep -woP '"url":"/[a-z]{2}/[a-z]{2}"' | cut -f4 -d'"' | cut -f2 -d'/' | sort -n | uniq | xargs | tr a-z A-Z)
    local isVPN=$(curl $curlArgs 'https://default.any-any.prd.api.hbomax.com/any/playback/v1/playbackInfo' -H "Cookie: st=${Token}" 2>&1)

    if [[ "$availableRegion" == *"$result"* ]] && [ -n "$result" ] && [ "$result" != "null" ]; then
        if [[ "$isVPN" == *"VPN"* ]]; then 
            echo -e " HBO Max:\t\t\t\t${Font_Red}No(VPN Detected; Region: $result)${Font_Suffix}"
        else
            echo -e " HBO Max:\t\t\t\t${Font_Green}Yes(Region: $result)${Font_Suffix}"
        fi
    else
        echo -e " HBO Max:\t\t\t\t${Font_Red}No/Not Available${Font_Suffix}"
    fi
}


function Test_ESPNPlus() {
    local espncookie=$(echo "$Media_Cookie" | sed -n '11p')
    local TokenContent=$(curl -${1} --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://espn.api.edge.bamgrid.com/token" -H "authorization: Bearer ZXNwbiZicm93c2VyJjEuMC4w.ptUt7QxsteaRruuPmGZFaJByOoqKvDP2a5YkInHrc7c" -d "$espncookie" 2>&1)
    local isBanned=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'forbidden-location')
    local is403=$(echo $TokenContent | grep '403 ERROR')

    if [ -n "$isBanned" ] || [ -n "$is403" ]; then
        echo -n -e "\r ESPN+:${Font_SkyBlue}[Sponsored by Jam]${Font_Suffix}\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    local fakecontent=$(echo "$Media_Cookie" | sed -n '10p')
    local refreshToken=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'refresh_token' | awk '{print $2}' | cut -f2 -d'"')
    local espncontent=$(echo $fakecontent | sed "s/ILOVESTAR/${refreshToken}/g")
    local tmpresult=$(curl -${1} --user-agent "${UA_Browser}" -X POST -sSL --max-time 10 "https://espn.api.edge.bamgrid.com/graph/v1/device/graphql" -H "authorization: ZXNwbiZicm93c2VyJjEuMC4w.ptUt7QxsteaRruuPmGZFaJByOoqKvDP2a5YkInHrc7c" -d "$espncontent" 2>&1)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r ESPN+:${Font_SkyBlue}[Sponsored by Jam]${Font_Suffix}\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local region=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'countryCode' | cut -f4 -d'"')
    local inSupportedLocation=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'inSupportedLocation' | awk '{print $2}' | cut -f1 -d',')

    if [[ "$region" == "US" ]] && [[ "$inSupportedLocation" == "true" ]]; then
        echo -n -e "\r ESPN+:${Font_SkyBlue}[Sponsored by Jam]${Font_Suffix}\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r ESPN+:${Font_SkyBlue}[Sponsored by Jam]${Font_Suffix}\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

}

function Test_Spotify() {
    local tmpresult=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -s --max-time 10 https://www.spotify.com/tw/signup 2>&1)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Spotify Region:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local country=$(echo $tmpresult | grep -Eo 'geoCountry.*","geoCountryMarket"')

    if [ -n "$country" ]; then
        echo -n -e "\r Spotify Region:\t\t\t${Font_Green}${country:13:-20}${Font_Suffix}\n"
        return
    fi
    echo -n -e "\r Spotify Region:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
}

function Test_Google() {
    local tmp=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsL --max-time 10 'https://bard.google.com/_/BardChatUi/data/batchexecute'   -H 'accept-language: en-US'   --data-raw 'f.req=[[["K4WWud","[[0],[\"en-US\"]]",null,"generic"]]]' 2>&1)
    if [[ "$tmp" == "curl"* ]]; then
        echo -n -e "\r Google Location:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local region=$(echo "$tmp" | grep K4WWud | jq .[0][2] | grep -Eo '\[\[\\"(.*)\\",\\"S' )
    echo -n -e "\r Google Location:\t\t\t${Font_Green}${region:4:-6}${Font_Suffix}\n"
}

function Test_GooglePlay() {
    local version="$1"
    local tmp=$(curl -$version -sL 'https://play.google.com' \
        -H 'accept-language: en-US;q=0.9' \
        -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' \
        --max-time 10 2>&1)

    if [[ $? -ne 0 ]]; then
        echo -e "${Red}Network Error${Suffix}"
        return
    fi

    local region=$(echo "$tmp" | grep -oP '<div class="yVZQTb">\K[^<(]+' | head -n 1)

    # 4. 兼容性备选方案：如果 -P 不支持，使用 sed 提取
    if [[ -z "$region" ]]; then
        region=$(echo "$tmp" | sed -n 's/.*<div class="yVZQTb">\([^<(]*\).*/\1/p' | head -n 1)
    fi

    if [[ -z "$region" ]]; then
        echo -n -e "\r Google Play:\t\t\t\t${Red}Unknown${Suffix}\n"
    else
       echo -n -e "\r Google Play:\t\t\t\t${Green}${region}${Suffix}\n"
    fi
}

function Test_Tiktok() {
    local result=$(curl $curlArgs --user-agent "${UA_Browser}" -${1} -fsSL --max-time 10  --output /dev/null -w %{url_effective} "https://www.tiktok.com/" 2>&1)
    local result1=$(curl $curlArgs --user-agent "${UA_Browser}" -${1} -fsSL --max-time 10 -X POST "https://www.tiktok.com/passport/web/store_region/" 2>&1)
    if [[ "$result" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Tiktok:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
        return
    elif [[ "$result" == "curl"* ]]; then
        echo -n -e "\r Tiktok:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local region="$(echo "${result1}" | jq ".data.store_region" | tr -d '"' )"
    if [[ "$result" == *"/about" ]] || [[ "$result" == *"/status"* ]] || [[ "$result" == *"landing"* ]]; then
        if [[ "$region" == "cn" ]]; then
            echo -n -e "\r Tiktok:\t\t\t\t${Font_Yellow}Provided by Douyin${Font_Suffix}\n"
            return
        else
            echo -n -e "\r Tiktok:\t\t\t\t${Font_Red}No  (Region: ${region^^})${Font_Suffix}\n"
            return
        fi
    else
        echo -n -e "\r Tiktok:\t\t\t\t${Font_Green}Yes (Region: ${region^^})${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Tiktok:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
}


function Test_ChatGPT() {
    local tmpresult=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsLI --max-time 10 "https://chatgpt.com" 2>&1)
    local tmpresult1=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsL --max-time 10 "https://ios.chat.openai.com" 2>&1)
    local cf_details=$(echo "$tmpresult1" | jq .cf_details)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r ChatGPT:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result1=$(echo "$tmpresult" | grep 'location' )
    if [ ! -n "$result1" ]; then
        if [[ "$tmpresult1" == *"blocked_why_headline"* ]]; then
            echo -n -e "\r ChatGPT:\t\t\t\t${Font_Red}No (Blocked)${Font_Suffix}\n"
            return
        fi
        if [[ "$tmpresult1" == *"unsupported_country_region_territory"* ]]; then
            echo -n -e "\r ChatGPT:\t\t\t\t${Font_Red}No (Unsupported Region)${Font_Suffix}\n"
            return
        fi
        if [[ "$cf_details" == *"(1)"* ]]; then
            echo -n -e "\r ChatGPT:\t\t\t\t${Font_Red}No (Disallowed ISP[1])${Font_Suffix}\n"
            return
        fi
        if [[ "$cf_details" == *"(2)"* ]]; then
            echo -n -e "\r ChatGPT:\t\t\t\t${Font_Red}No (Disallowed ISP[2])${Font_Suffix}\n"
            return
        fi
    	echo -n -e "\r ChatGPT:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
    	local region1=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsL --max-time 10 "https://chatgpt.com/cdn-cgi/trace" 2>&1 | grep "loc=" | awk -F= '{print $2}')
        if [[ "$cf_details" == *"(1)"* ]]; then
            echo -n -e "\r ChatGPT:\t\t\t\t${Font_Yellow}Web Only (Disallowed ISP[1])${Font_Suffix}\n"
            return
        fi
        if [[ "$cf_details" == *"(2)"* ]]; then
            echo -n -e "\r ChatGPT:\t\t\t\t${Font_Yellow}Web Only (Disallowed ISP[2])${Font_Suffix}\n"
            return
        fi
        echo -n -e "\r ChatGPT:\t\t\t\t${Font_Green}Yes (Region: ${region1})${Font_Suffix}\n"
    fi
}

function Test_Sora() {
    local tmpresult=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsLI --max-time 10 "https://sora.com" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Sora:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result1=$(echo "$tmpresult" | grep 'location'  )
    if [ ! -n "$result1" ]; then
    	echo -n -e "\r Sora:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
    	local region1=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsL --max-time 10 "https://sora.com/cdn-cgi/trace" 2>&1 | grep "loc=" | awk -F= '{print $2}')
        echo -n -e "\r Sora:\t\t\t\t\t${Font_Green}Yes (Region: ${region1})${Font_Suffix}\n"
    fi
}

function Test_Gemini_location() {
    local tmp=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsL --max-time 10 'https://gemini.google.com/_/BardChatUi/data/batchexecute'   -H 'accept-language: en-US'   --data-raw 'f.req=[[["K4WWud","[[0],[\"en-US\"]]",null,"generic"]]]' 2>&1)
    if [[ "$tmp" == "curl"* ]]; then
        echo -n -e "\r Google Gemini Location:\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local region=$(echo "$tmp" | grep K4WWud | jq .[0][2] | grep -Eo '\[\[\\"(.*)\\",\\"S' )
    echo -n -e "\r Google Gemini Location:\t\t${Font_Yellow}${region:4:-6}${Font_Suffix}\n"
}

function Test_Copilot() {
    local tmp=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsL --max-time 10 "https://copilot.microsoft.com/" 2>&1)
    local tmp2=$(curl $curlArgs -${1} --user-agent "${UA_Browser}" -SsL --max-time 10 "https://copilot.microsoft.com/turing/conversation/chats?bundleVersion=1.1342.3-cplt.12"  2>&1)
    if [[ "$tmp" == "curl"* ]]; then
        echo -n -e "\r Microsoft Copilot:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo "$tmp2" | jq .result.value  2>&1 | tr -d '"' 2>&1) 
    local region=$(echo "$tmp" | sed -n 's/.*RevIpCC:"\([^"]*\)".*/\1/p' )
    if [[ "$result" == "Success" ]];then
        echo -n -e "\r Microsoft Copilot:\t\t\t${Font_Green}Yes (Region: ${region^^})${Font_Suffix}\n"
    else 
        echo -n -e "\r Microsoft Copilot:\t\t\t${Font_Red}No  (Region: ${region^^})${Font_Suffix}\n"
    fi
}

function echo_Result() {
    for((i=0;i<${#array[@]};i++))
    do
        echo "$result" | grep "${array[i]}"
        # sleep 0.03
    done;
}

if [ -n "$func" ]; then
    echo -e "${Font_Green}IPv4:${Font_Suffix}"
    $func 4
    echo -e "${Font_Green}IPv6:${Font_Suffix}"
    $func 6
    exit
fi

function Global_UnlockTest() {
    echo ""
    echo "============[ Multination ]============"
	echo -e "\n"
	
		Test_DisneyPlus "$1"
        Test_Netflix "$1"
		Test_NetflixCDN "$1"
		Test_Google "$1"
		Test_GooglePlay "$1"
        Test_YouTube_Premium "$1"
        #Test_YouTube_CDN "$1"
		Test_PrimeVideo_Region "$1"
		Test_HBO "$1"
        Test_Spotify "$1"
        Test_Tiktok "$1"
		Test_Steam "$1"
		
	echo ""	
    echo "======================================="
}

function AI_UnlockTest() {
    echo "============[ AI Platform ]============"
	Test_Gemini_location "$1"
    Test_ChatGPT "$1"
    Test_Sora "$1"
    Test_Copilot "$1"
    echo "======================================="
}

function CheckV4() {
    if [[ "$language" == "e" ]]; then
        if [[ "$NetworkType" == "6" ]]; then
            isv4=0
            echo -e "${Font_SkyBlue}User Choose to Test Only IPv6 Results, Skipping IPv4 Testing...${Font_Suffix}"
        else
            echo -e " ${Font_SkyBlue}** Checking Results Under IPv4${Font_Suffix} "
            echo "--------------------------------"
			#fetchIP "$NetworkType"
            #echo -e " ${Font_SkyBlue}** Your Network Provider: AS${local_as4} ${local_isp4} (${local_ipv4_asterisk})${Font_Suffix} "
            if [ -n  "$local_ipv4"  ]; then
                isv4=1
            else
                echo -e "${Font_SkyBlue}No IPv4 Connectivity Found, Abort IPv4 Testing...${Font_Suffix}"
                isv4=0
            fi

            echo ""
        fi
    else
        if [[ "$NetworkType" == "6" ]]; then
            isv4=0
            echo -e "${Font_SkyBlue}用户选择只检测IPv6结果，跳过IPv4检测...${Font_Suffix}"
        else
            echo -e " ${Font_SkyBlue}** 正在测试IPv4解锁情况${Font_Suffix} "
            echo "--------------------------------"
			#fetchIP "$NetworkType"
            #echo -e " ${Font_SkyBlue}** 您的网络为: AS${local_as4} ${local_isp4} (${local_ipv4_asterisk})${Font_Suffix} "
            if [ -n  "$local_ipv4"  ]; then
                isv4=1
            else
                echo -e "${Font_SkyBlue}当前网络不支持IPv4,跳过...${Font_Suffix}"
                isv4=0
            fi

            echo ""
        fi
    fi
}

function CheckV6() {
    if [[ "$language" == "e" ]]; then
        if [[ "$NetworkType" == "4" ]]; then
            isv6=0
            if [ -z "$usePROXY" ]; then
                echo -e "${Font_SkyBlue}User Choose to Test Only IPv4 Results, Skipping IPv6 Testing...${Font_Suffix}"
            fi
        else
            if [ -n  "$local_ipv6"  ]; then
                echo ""
                echo ""
                echo -e " ${Font_SkyBlue}** Checking Results Under IPv6${Font_Suffix} "
                echo "--------------------------------"
				#fetchIP "$NetworkType"
                #echo -e " ${Font_SkyBlue}** Your Network Provider:  AS${local_as6} ${local_isp6} (${local_ipv6_asterisk})${Font_Suffix} "
                isv6=1
            else
                echo -e "${Font_SkyBlue}No IPv6 Connectivity Found, Abort IPv6 Testing...${Font_Suffix}"
                isv6=0
            fi
            echo -e ""
        fi

    else
        if [[ "$NetworkType" == "4" ]]; then
            isv6=0
            if [ -z "$usePROXY" ]; then
                echo -e "${Font_SkyBlue}用户选择只检测IPv4结果，跳过IPv6检测...${Font_Suffix}"
            fi
        else
            if [ -n  "$local_ipv6"  ]; then
                echo ""
                echo ""
                echo -e " ${Font_SkyBlue}** 正在测试IPv6解锁情况${Font_Suffix} "
                echo "--------------------------------"
				#fetchIP "$NetworkType"
                #echo -e " ${Font_SkyBlue}** 您的网络为: AS${local_as6} ${local_isp6} (${local_ipv6_asterisk})${Font_Suffix} "
                isv6=1
            else
                echo -e "${Font_SkyBlue}当前主机不支持IPv6,跳过...${Font_Suffix}"
                isv6=0
            fi
            echo -e ""
        fi
    fi
}

function parse_json() {
    local data="$1"
    local field="$2"
    if command -v jq &> /dev/null; then
        echo "$data" | jq -r ".$field" | xargs
    else
        echo "$data" | grep -oP "\"$field\":\s*\"\K[^\"]+" | head -1
    fi
}

function FetchIP() {
    local version="$1"
    local data=""
    
    # 尝试源 A: ip.sb (支持 v4/v6)
    data=$(curl -$version -s --connect-timeout 5 -A "Mozilla/5.0" https://api.ip.sb/geoip 2>/dev/null)
    
    # 如果源 A 失败，尝试源 B: ip-api.com
    if [[ -z "$data" || "$data" != *"country"* ]]; then
        data=$(curl -$version -s --connect-timeout 5 http://ip-api.com/json 2>/dev/null)
    fi

    if [[ -n "$data" && ( "$data" == *"country"* || "$data" == *"success"* ) ]]; then
        local ip=$(parse_json "$data" "$( [[ "$data" == *"query"* ]] && echo "query" || echo "ip" )")
        local country_name=$(parse_json "$data" "country")
        local country_code=$(parse_json "$data" "country_code")
        [[ -z "$country_code" ]] && country_code=$(parse_json "$data" "countryCode") # 兼容 ip-api
        
        local org=$(parse_json "$data" "isp")
        [[ -z "$org" || "$org" == "null" ]] && org=$(parse_json "$data" "organization")
        [[ -z "$org" || "$org" == "null" ]] && org=$(parse_json "$data" "org")

        echo -e "${Yellow}Address:\t${Suffix} ${Blue}${ip}${Suffix}"
        echo -e "${Yellow}ORG    :\t${Suffix} ${Blue}${org}  ${country_name}${Suffix}"
        
    else
        echo -e "${Yellow}IPv$version Status:${Suffix} ${Red}Not detected or unable to connect/未检测到或无法连接${Suffix}"
    fi
}


function Goodbye() {
    if [[ "$language" == "e" ]]; then
        echo -e "${Font_Green}Testing Done! Thanks for Using This Script! ${Font_Suffix}"
    else
        echo -e "${Font_Green}本次测试已结束，感谢使用此脚本 ${Font_Suffix}"
    fi
}

clear

function ScriptTitle() {
    if [[ "$language" == "e" ]]; then
        echo -e " [Platform Region Test]"
        echo ""
        echo -e " ** Test Starts At: $(date)"
        echo ""
    else
        echo -e " [平台区域测试]"
        echo ""
        echo -e " ** 测试时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo ""
    fi
}
ScriptTitle

function Start() {
    if [[ "$language" == "e" ]]; then
        echo -e "${Font_Blue}Please Select Test Region or Press ENTER to Test All Regions${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number  [0]: [ Multination Only ]${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number  [1]: [ Multination and AI Platforms ]${Font_Suffix}"
        read -p "Please Input the Correct Number or Press ENTER:" num
    else
        echo -e "${Font_Blue}请选择检测项目，直接按回车将进行全区域检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字  [0]: [ 跨国平台 ]检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字  [1]: [ 跨国平台+AI平台  ]检测${Font_Suffix}"
        read -p "请输入正确数字或直接按回车:" num
    fi
}
Start


function RunScript() {

    if [[ -n "${num}" ]]; then
        if [[ "$num" -eq 1 ]]; then
            clear
            ScriptTitle
            CheckV4
            if [[ "$isv4" -eq 1 ]]; then
			    FetchIP 4
                Global_UnlockTest 4
                AI_UnlockTest 4
            fi
            CheckV6
            if [[ "$isv6" -eq 1 ]]; then
			    FetchIP 6
                Global_UnlockTest 6
                AI_UnlockTest 6
            fi
            Goodbye

        elif [[ "$num" -eq 0 ]]; then
            clear
            ScriptTitle
            CheckV4
            if [[ "$isv4" -eq 1 ]]; then
			    FetchIP 4
                Global_UnlockTest 4
            fi
            CheckV6
            if [[ "$isv6" -eq 1 ]]; then
			    FetchIP 6
                Global_UnlockTest 6
            fi
            Goodbye

        else
            echo -e "${Font_Red}请重新执行脚本并输入正确号码${Font_Suffix}"
            echo -e "${Font_Red}Please Re-run the Script with Correct Number Input${Font_Suffix}"
            return
        fi
    else
        clear
        ScriptTitle
        CheckV4
        if [[ "$isv4" -eq 1 ]]; then
		    FetchIP 4
            Global_UnlockTest 4
            AI_UnlockTest 4
        fi
        CheckV6
        if [[ "$isv6" -eq 1 ]]; then
		    FetchIP 6
            Global_UnlockTest 6
            AI_UnlockTest 6
        fi
        Goodbye
    fi
}
wait
RunScript
