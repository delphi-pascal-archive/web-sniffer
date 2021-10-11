{
    websniffer - websniffer.dpr (Ver1.1)(HTTP connection analysis)
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
program WebSniffer;

uses
  Forms,Windows,
  MainForm in 'MainForm.pas' {Form1},
  SniffThread in 'SniffThread.pas';

{$R *.res}
 var
  ExtendedStyle : Integer;
begin
  Application.Initialize;
  //Get the Extended Styles of the Application, by passing its
  //handle to GetWindowLong
  ExtendedStyle := GetWindowLong(Application.Handle, GWL_EXSTYLE);
  //Now, set the Extended Style by doing a bit masking operation.
  //OR in the WS_EX_TOOLWINDOW bit, and AND out the WS_EXAPPWINDOW bit
  //This effectively converts the application from an App Windows to a
  //Tool Window.
  SetWindowLong(Application.Handle, GWL_EXSTYLE, ExtendedStyle OR WS_EX_TOOLWINDOW AND NOT WS_EX_APPWINDOW);
 //SetWindowLong(Application.Handle, GWL_EXSTYLE, ExtendedStyle OR WS_EX_TOOLWINDOW );
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
