{
    websniffer - Buffer.pas (Ver1.1)(HTTP connection analysis)
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
unit Buffer;

interface
type
 Tbuf=class
 public
   Size,DataLen:Cardinal;
   Buffer: Pointer;
   constructor Create(ASize:Cardinal);
   procedure Add(buf:PChar;Len:cardinal);
   procedure Resize(NewSize:cardinal);
   destructor Free;
  end;
 TWindowBuf=class
 public
   Size:Cardinal;
   Buffer: Pointer;
   constructor Create;
   procedure Write(seq:cardinal;buf:PChar;Len:cardinal);
   procedure Read(seq:cardinal;var buf:PChar);
   destructor Free;
  end;
implementation
constructor TWindowBuf.create;
begin
  Size:=65536+2000;
  GetMem(Buffer, Size);
end;
procedure TWindowBuf.Write(seq:cardinal;buf:PChar;Len:cardinal);
var Wseq,WseqEnd:Word;
begin
  Wseq:=Word(seq);
  WseqEnd:=Word(seq+Len);
  Move(buf^, (PChar(buffer)+Wseq)^, Len);
  if Wseq>WseqEnd then
    Move((PChar(buffer)+65536)^, (PChar(buffer))^, WseqEnd);
  if Wseq<2000 then
    Move((PChar(buffer)+Wseq)^,(PChar(buffer)+65536+Wseq)^, 2000-Wseq);
end;
procedure TWindowBuf.Read(seq:cardinal;var buf:PChar);
begin
  buf:=PChar(buffer)+Word(seq);
end;
destructor TWindowBuf.free;
begin
  FreeMem(Buffer, Size);
end;


Constructor Tbuf.create(ASize:Cardinal);
begin
  Size:=ASize; DataLen:=0;
  GetMem(Buffer, Size);
end;
procedure Tbuf.Resize(NewSize:cardinal);
var NewBuffer:PChar;
begin
  if NewSize< DataLen then NewSize:=DataLen;
  GetMem(NewBuffer, NewSize);
  Move(Buffer^, NewBuffer^, DataLen);
  FreeMem(Buffer,Size);
  Size:=NewSize;
  Buffer:=NewBuffer;
end;
procedure Tbuf.Add(buf:PChar;Len:cardinal);
begin
  if (DataLen+Len)>Size then Resize(Size*2);
  Move(buf^, (PChar(buffer)+DataLen)^, Len);
  DataLen:=DataLen+Len;
end;
destructor Tbuf.free;
begin
  FreeMem(Buffer, Size);
end;

end.
