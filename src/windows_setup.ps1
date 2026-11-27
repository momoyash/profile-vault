$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

try {
    $browser = if ($env:PV_BRAVE) { 'Brave' } else { 'Chrome' }
    if ($env:PV_BRAVE -and $env:PV_CHROME) {
        $form = New-Object System.Windows.Forms.Form
        $form.Text = 'Choose a browser to protect'
        $form.StartPosition = 'CenterScreen'
        $form.FormBorderStyle = 'FixedDialog'
        $form.MinimizeBox = $false
        $form.MaximizeBox = $false
        $form.AutoSize = $true
        $form.AutoSizeMode = 'GrowAndShrink'
        $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
        $buttons.AutoSize = $true
        $buttons.Padding = New-Object System.Windows.Forms.Padding(12)
        foreach ($name in 'Brave','Chrome') {
            $button = New-Object System.Windows.Forms.Button
            $button.Text = $name
            $button.Add_Click({
                $form.Tag = $this.Text
                $form.DialogResult = 'OK'
            })
            $buttons.Controls.Add($button)
        }
        $form.Controls.Add($buttons)
        if ($form.ShowDialog() -ne 'OK') { return }
        $browser = $form.Tag
    }
    $browserExe = if ($browser -eq 'Brave') { $env:PV_BRAVE } else { $env:PV_CHROME }
    $choice = [System.Windows.Forms.MessageBox]::Show(
        "Create a new encrypted profile container? Choose Yes to open the VeraCrypt wizard. Select Create an encrypted file container, then Standard VeraCrypt volume. Give it a new file name and a password. Choose No if you already have a dedicated container.",
        "Protected $browser profile", 'YesNoCancel', 'Question')
    if ($choice -eq 'Cancel') { return }
    if ($choice -eq 'Yes') {
        $wizard = Join-Path (Split-Path -Parent $env:PV_VC) 'VeraCrypt Format.exe'
        Start-Process -FilePath $wizard -Wait
    }

    $file = New-Object System.Windows.Forms.OpenFileDialog
    $file.Title = 'Choose the encrypted VeraCrypt container for this profile'
    $file.Filter = 'VeraCrypt volumes (*.hc)|*.hc|All files (*.*)|*.*'
    if ($file.ShowDialog() -ne 'OK') { return }

    $letters = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name[0] })
    $letter = 90..68 | ForEach-Object { [char]$_ } | Where-Object { $_ -notin $letters } | Select-Object -First 1
    if (!$letter) { throw 'No free drive letter is available.' }

    $save = New-Object System.Windows.Forms.SaveFileDialog
    $save.Title = 'Save your protected profile shortcut'
    $save.Filter = 'Windows shortcuts (*.lnk)|*.lnk'
    $save.DereferenceLinks = $false
    $save.InitialDirectory = [Environment]::GetFolderPath('DesktopDirectory')
    $save.FileName = "Protected $browser.lnk"
    if ($save.ShowDialog() -ne 'OK') { return }

    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($save.FileName)
    $link.TargetPath = $env:PV_LAUNCHER
    $link.Arguments = '"{0}" {1} {2}' -f $file.FileName, $letter, $browser
    $link.IconLocation = "$browserExe,0"
    $link.Description = "Unlock the encrypted $browser profile"
    $link.Save()
    [void][System.Windows.Forms.MessageBox]::Show(
        "Open the saved shortcut to enter your password. Close the protected $browser windows to lock the volume. The shortcut clears VeraCrypt's shared password cache each time it opens.",
        'Shortcut ready', 'OK', 'Information')
} catch {
    [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Profile Vault setup', 'OK', 'Error')
    exit 1
}
