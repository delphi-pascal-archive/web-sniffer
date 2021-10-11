{
    websniffer - mainform.pas (Ver1.1)(HTTP connection analysis)
    Copyright (C) 2005 Josef Schützenberger

    websniffer is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    websniffer is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with websniffer; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
}
unit MainForm;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, Menus, StdCtrls, Buttons, ComCtrls,PcapNet,SniffThread, ExtCtrls,ShellAPI,
  ImgList;

type
  TForm1 = class(TForm)
    GroupBox2: TGroupBox;
    ComboBoxInterface: TComboBox;
    BitBtnStart: TBitBtn;
    BitBtn3: TBitBtn;
    GroupBox1: TGroupBox;
    EditFolder: TEdit;
    SpeedButton1: TSpeedButton;
    CheckBoxFolders: TCheckBox;
    StatusBar: TStatusBar;
    CheckBoxLog: TCheckBox;
    Image1: TImage;
    PopupMenu1: TPopupMenu;
    Show1: TMenuItem;
    Exit1: TMenuItem;
    ImageList1: TImageList;
    procedure SpeedButton1Click(Sender: TObject);
    procedure ComboBoxInterfaceDropDown(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure BitBtnStartClick(Sender: TObject);
    procedure BitBtn3Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure Show1Click(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure Exit1Click(Sender: TObject);
  private
    procedure SaveIniFile;
    procedure LoadIniFile;
    procedure FileSave(var Filename:String;Host:String;Len:Integer);
    procedure HandleError(const msg:String);
    procedure Minimize(Sender: TObject);
  public
   IconNotifyData : TNotifyIconData;
   procedure WndProc(var Msg : TMessage); override;
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}
uses FileCtrl,IniFiles,StrUtils,conitem;

procedure TForm1.FileSave(var Filename:String;Host:String;Len:Integer);
begin
  if not CheckBoxFolders.Checked  then FileName:=AnsiReplaceText(FileName,'\','_');
  FileName:=IncludeTrailingPathDelimiter(EditFolder.Text)+FileName;
  form1.StatusBar.Panels[1].Text:=Filename;
end;
procedure TForm1.HandleError(const msg:String);
begin
  form1.StatusBar.Panels[1].Text:=msg;
end;
procedure TForm1.SaveIniFile;
var
  IniFileVar: TIniFile;
begin
  IniFileVar := TIniFile.create(ExtractFileDir(ParamStr(0))+'\WebSniffer.ini');
  IniFileVar.WriteString('Folder', 'Directory', EditFolder.Text);
  IniFileVar.WriteBool('Folder', 'Subfolder', CheckBoxFolders.Checked);
  IniFileVar.WriteString('Interface', 'Name', ComboBoxInterface.Text);
  IniFileVar.WriteBool('Interface', 'Log', CheckBoxLog.Checked);
  IniFileVar.free;
end;

Procedure TForm1.LoadIniFile;
var
  IniFileVar: TIniFile;
begin
  IniFileVar := TIniFile.create(ExtractFileDir(ParamStr(0))+'\WebSniffer.ini');
  EditFolder.Text := IniFileVar.ReadString('Folder', 'Directory', '.\data');
  CheckBoxFolders.Checked:=IniFileVar.ReadBool('Folder', 'Subfolder', false);
  ComboBoxInterface.Text := IniFileVar.ReadString('Interface', 'Name', '?????');
  CheckBoxLog.Checked:=IniFileVar.ReadBool('Interface', 'Log', false);
  IniFileVar.Free;
end;

procedure TForm1.SpeedButton1Click(Sender: TObject);
var dir:String;
begin
  dir:=EditFolder.Text;
  SelectDirectory('Select the folder where all captured files will be saved. ','c:\',dir);
  EditFolder.Text:=dir;
  EditFolder.SetFocus;
end;

procedure TForm1.ComboBoxInterfaceDropDown(Sender: TObject);
var alldevs,dev:pcap_if; ErrBuf:TErrBuf;
    line:String;i:integer;
begin
  ComboBoxInterface.items.Clear;
  if Handlewpcap=0 then
  begin
    Application.MessageBox('No interfaces found! Make sure pcap/Winpcap is installed.', 'Error', MB_OK		);
    exit;
  end;
  i:=pcap_findalldevs(Pointer(@alldevs),@ErrBuf);
  if i<>0 then   begin
    Application.MessageBox('No interfaces found! Make sure pcap/Winpcap is installed.', 'Error', MB_OK		);
    exit;
  end;
  dev:=alldevs;
  while dev<>nil do begin
    Line:=dev.name;
    ComboBoxInterface.items.Add(Line);
    dev:=dev.next;
  end;
  pcap_freealldevs(alldevs);
end;

procedure TForm1.FormActivate(Sender: TObject);
begin
  LoadIniFile;
end;

procedure TForm1.BitBtnStartClick(Sender: TObject);
var alldevs,dev,seldev:pcap_if;ErrBuf:TErrBuf;
    i:integer;promisc:integer;adhandle:Pointer;
begin
  if Handlewpcap=0 then
  begin
     Application.MessageBox('No interfaces found! Make sure pcap/Winpcap is installed.', 'Error', MB_OK		);
     exit;
  end;
  SaveIniFile;
  FillChar(ErrBuf, sizeof(ErrBuf), #0);
  i:=pcap_findalldevs(Pointer(@alldevs),@ErrBuf);
  if i<>0 then
  begin
    Application.MessageBox('No interfaces found! Make sure pcap/Winpcap is installed.', 'Error', MB_OK		);
    exit;
  end;
  dev:=alldevs; seldev:=nil;
  while dev<>nil do
  begin
    if  ComboBoxInterface.Text=dev.name then seldev:=dev;
    dev:=dev.next;
  end;
  if seldev=nil then
  begin
    Application.MessageBox('Select interface.', 'Look', MB_OK);
    pcap_freealldevs(alldevs);
    exit;
  end;
  BitBtnStart.Enabled:=false;
  StatusBar.Panels[1].Text:='sniffing started';
  Imagelist1.GetIcon(0,application.Icon);
  IconNotifyData.hIcon := Application.Icon.Handle;
  Shell_NotifyIcon(NIM_MODIFY,@IconNotifyData);
  promisc:=0;
  ConList:=TConlist.Create;
  ConList.OnSaveFile:=FileSave;
  ConList.OnPacketMessage:=nil;
  ConList.OnError:=HandleError;
  adhandle:= pcap_open_live(seldev.name,	// name of the device
   			 65536,		// portion of the packet to capture.
   			 // 65536 grants that the whole packet will be captured on all the MACs.
        		 promisc,     	// promiscuous mode
			 1000,		// read timeout
			 @errbuf );    	// error buffer
  pcap_freealldevs(alldevs);
  SniffThread1:=TSniffThread.Create(true);
  SniffThread1.run(adhandle);
  SniffThread1.Resume;
end;


procedure TForm1.BitBtn3Click(Sender: TObject);
begin
  BitBtnStart.Enabled:=true;
  StatusBar.Panels[1].Text:='stopped';
  if SniffThread1<> nil then SniffThread1.stop;
  Imagelist1.GetIcon(1,application.Icon);
  IconNotifyData.hIcon := Application.Icon.Handle;
  Shell_NotifyIcon(NIM_MODIFY,@IconNotifyData);
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  //Set up the IconNotifyData structure so that it receives
  //the window messages sent to the application and displays
  //the application's tips
  with IconNotifyData do
  begin
    hIcon := Application.Icon.Handle;
    uCallbackMessage := WM_USER + 1;
    cbSize := sizeof(IconNotifyData);
    Wnd := Handle;
    uID := 100;
    uFlags := NIF_MESSAGE + NIF_ICON + NIF_TIP;
  end;
  //Copy the Application's Title into the tip for the icon
  StrPCopy(IconNotifyData.szTip, Application.Title);
  //Add the Icon to the system tray and use the
  //the structure and its values
  Shell_NotifyIcon(NIM_ADD, @IconNotifyData);
  Application.OnMinimize := Minimize;

end;                        
procedure TForm1.Minimize(Sender: TObject);
begin
  ShowWindow(Application.Handle, SW_HIDE);
end;

procedure TForm1.WndProc(var Msg : TMessage);
var
  p : TPoint;
begin
  case Msg.Msg of
    WM_USER + 1:
    case Msg.lParam of
      WM_RBUTTONDOWN: begin
                        GetCursorPos(p);
                        PopupMenu1.Popup(p.x, p.y);
                      end;
      WM_LBUTTONDOWN: begin
                        Show1Click(self);
                      end;
    end;
  end;
  inherited;
end;


procedure TForm1.Show1Click(Sender: TObject);
begin
  Application.Restore;
  BringToFront;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  Shell_NotifyIcon(NIM_DELETE, @IconNotifyData);
end;

procedure TForm1.Exit1Click(Sender: TObject);
begin
  if SniffThread1<> nil then SniffThread1.stop;
  Shell_NotifyIcon(NIM_DELETE, @IconNotifyData);
  close;
end;

end.
