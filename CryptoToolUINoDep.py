#!/usr/bin/env python3

"""
Crypto Tool
"""


import wx
import pyDes
import pyaes
from binascii import hexlify, unhexlify
import sys
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT

import ctypes
from wx.core import ID_ANY

# Query DPI Awareness (Windows 10 and 8)
awareness = ctypes.c_int()
errorCode = ctypes.windll.shcore.GetProcessDpiAwareness(
    0, ctypes.byref(awareness))
print(awareness.value)
# Set DPI Awareness  (Windows 10 and 8)
errorCode = ctypes.windll.shcore.SetProcessDpiAwareness(2)
# the argument is the awareness level, which can be 0, 1 or 2:
# for 1-to-1 pixel control I seem to need it to be non-zero (I'm using level 2)
# Set DPI Awareness  (Windows 7 and Vista)
success = ctypes.windll.user32.SetProcessDPIAware()
# behaviour on later OSes is undefined,
# although when I run it on my Windows 10 machine, 
# it seems to work with effects identical to SetProcessDpiAwareness(1


ENC = 1
DEC = 0
algList = ['aes', 'des', '3des2key', '3des3key', 'sm4']
modeList = ['ecb', 'cbc']


def check_data_format(alg, mode, key, iv, data):
    if alg == 'aes':
        if mode == 'cbc' and len(iv) != 32:
            return False, 'iv length must be 16, please input right iv.'
        if len(key) != 32:
            return False, 'key length must be 16, please input right key.'
        if len(data) % 32 != 0:
            return False, 'data length must be 16 * N, please input right data.'

    elif alg == 'des':
        if mode == 'cbc' and len(iv) != 16:
            return False, 'iv length must be 8, please input right iv.'
        if len(key) != 16:
            return False, 'key length must be 8, please input right key.'
        if len(data) % 16 != 0:
            return False, 'data length must be 8 * N, please input right data.'

    elif alg == '3des2key':
        if mode == 'cbc' and len(iv) != 16:
            return False, 'iv length must be 8, please input right iv.'
        if len(key) != 32:
            return False, 'key length must be 16, please input right key.'
        if len(data) % 16 != 0:
            return False, 'data length must be 8 * N, please input right data.'

    elif alg == '3des3key':
        if mode == 'cbc' and len(iv) != 16:
            return False, 'iv length must be 8, please input right iv.'
        if len(key) != 48:
            return False, 'key length must be 24, please input right key.'
        if len(data) % 16 != 0:
            return False, 'data length must be 8 * N, please input right data.'

    elif alg == 'sm4':
        if mode == 'cbc' and len(iv) != 32:
            return False, 'iv length must be 16, please input right iv.'
        if len(key) != 32:
            return False, 'key length must be 16, please input right key.'
        if len(data) % 32 != 0:
            return False, 'data length must be 16 * N, please input right data.'

    return True, 'data format correct'


def SymmCryptoCompute(alg, mode, op, key, iv, data):
    if alg not in algList:
        return False, "algorithm does't support."
    ret, message = check_data_format(alg, mode, key, iv, data)
    if ret == False:
        return ret, message

    out = ''

    if alg == 'aes':
        if op == ENC:
            for i in range(int(len(data) / 32)):
                if mode == 'ecb':
                    aes = pyaes.AESModeOfOperationECB(unhexlify(key))
                elif mode == 'cbc':
                    aes = pyaes.AESModeOfOperationCBC(
                        unhexlify(key), unhexlify(iv))
                iv = bytes.hex(aes.encrypt(unhexlify(data[i*32:(i+1)*32])))
                out += iv
        elif op == DEC:
            for i in range(int(len(data) / 32)):
                if mode == 'ecb':
                    aes = pyaes.AESModeOfOperationECB(unhexlify(key))
                elif mode == 'cbc':
                    aes = pyaes.AESModeOfOperationCBC(
                        unhexlify(key), unhexlify(iv))
                iv = data[i*32:(i+1)*32]
                out += bytes.hex(aes.decrypt(unhexlify(data[i*32:(i+1)*32])))

    elif alg == 'des' or alg == '3des2key' or alg == '3des3key':
        if alg == 'des':
            des = pyDes.des
        else:
            des = pyDes.triple_des
        if mode == 'ecb':
            k = des(unhexlify(key), pyDes.ECB, None,
                    pad=None, padmode=pyDes.PAD_NORMAL)
        elif mode == 'cbc':
            k = des(unhexlify(key), pyDes.CBC, unhexlify(
                iv), pad=None, padmode=pyDes.PAD_NORMAL)
        if op == ENC:
            out = bytes.hex(k.encrypt(unhexlify(data)))
        elif op == DEC:
            out = bytes.hex(k.decrypt(unhexlify(data)))

    elif alg == 'sm4':
        sm4 = Sm4()
        if op == ENC:
            sm4.sm4_set_key(unhexlify(key), ENCRYPT)
        elif op == DEC:
            sm4.sm4_set_key(unhexlify(key), DECRYPT)
        if mode == 'ecb':
            out = bytes.hex(bytes(sm4.sm4_crypt_ecb(unhexlify(data))))
        elif mode == 'cbc':
            out = bytes.hex(bytes(sm4.sm4_crypt_cbc(
                unhexlify(iv), unhexlify(data))))
    return True, str(out)


class TextFrame(wx.Frame):

    def __init__(self, parent, title):
        super(TextFrame, self).__init__(parent, id=ID_ANY, title='Crypto Tool',
                                        size=(800, 960))
        self.InitStatusBar()
        self.InitUI()        
        self.Centre()
        self.Show()

    def InitUI(self):
        panel = wx.Panel(self, -1)

        self.keyLabel = wx.StaticText(panel, label="密钥:")
        self.keyText = wx.TextCtrl(
            panel, size=(-1, 40), style=wx.TE_CHARWRAP | wx.TE_MULTILINE)
        self.keyText.SetInsertionPoint(0)

        self.ivLabel = wx.StaticText(panel, label="IV:")
        self.ivText = wx.TextCtrl(
            panel, size=(-1, 40), style=wx.TE_CHARWRAP | wx.TE_MULTILINE)
        self.keyText.SetInsertionPoint(0)

        self.plainLabel = wx.StaticText(panel, label="明文:")
        self.plainText = wx.TextCtrl(
            panel, size=(-1, 100), style=wx.TE_CHARWRAP | wx.TE_MULTILINE)

        self.cipherLabel = wx.StaticText(panel, label="密文:")
        self.cipherText = wx.TextCtrl(
            panel, size=(-1, 100), style=wx.TE_CHARWRAP | wx.TE_MULTILINE)

        self.outdataLabel = wx.StaticText(panel, label="输出信息:")
        self.outdataText = wx.TextCtrl(
            panel, size=(-1, 400), style=wx.TE_CHARWRAP | wx.TE_MULTILINE)

        fgs = wx.FlexGridSizer(6, 2, 9, 25)
        fgs.AddMany([(self.keyLabel), (self.keyText, 1, wx.EXPAND),
                     (self.ivLabel), (self.ivText, 1, wx.EXPAND),
                     (self.plainLabel), (self.plainText, 1, wx.EXPAND),
                     (self.cipherLabel), (self.cipherText, 1, wx.EXPAND),
                     (self.outdataLabel), (self.outdataText, 1, wx.EXPAND)])
        fgs.AddGrowableRow(2, 1)
        fgs.AddGrowableRow(3, 1)
        fgs.AddGrowableRow(4, 1)
        fgs.AddGrowableCol(1, 1)

        self.algList = ['aes', 'des', '3des2key', '3des3key', 'sm4']
        self.algLabel = wx.StaticText(panel, label="算法:")
        self.algChoice = wx.Choice(panel, choices=self.algList)
        self.algChoice.SetSelection(0)

        self.modeList = ['ecb', 'cbc']
        self.modeLabel = wx.StaticText(panel, label="模式:")
        self.modeChoice = wx.Choice(panel, choices=self.modeList)
        self.modeChoice.SetSelection(0)

        self.encButton = wx.Button(panel, label="加密")
        self.Bind(wx.EVT_BUTTON, self.OnClickEnc, self.encButton)
        self.encButton.SetDefault()

        self.decButton = wx.Button(panel, label="解密")
        self.Bind(wx.EVT_BUTTON, self.OnClickDec, self.decButton)
        self.decButton.SetDefault()

        choiceBox = wx.BoxSizer(wx.HORIZONTAL)
        choiceBox.Add(self.algLabel, flag=wx.ALL, border=15)
        choiceBox.Add(self.algChoice, flag=wx.ALL, border=15)
        choiceBox.Add(self.modeLabel, flag=wx.ALL, border=15)
        choiceBox.Add(self.modeChoice, flag=wx.ALL, border=15)
        choiceBox.Add(self.encButton, flag=wx.ALL, border=15)
        choiceBox.Add(self.decButton, flag=wx.ALL, border=15)

        hbox = wx.BoxSizer(wx.VERTICAL)
        hbox.Add(fgs, proportion=1, flag=wx.ALL | wx.EXPAND, border=15)
        hbox.Add(choiceBox, proportion=1, flag=wx.ALL | wx.EXPAND, border=15)

        panel.SetSizer(hbox)

    def InitStatusBar(self):
        self.statusbar = self.CreateStatusBar()
        self.statusbar.SetFieldsCount(3)
        self.statusbar.SetStatusWidths([-2, -5, -1])
        self.statusbar.SetStatusText("Use wxPython", 0)
        self.statusbar.SetStatusText("zhangqinlei@gmail.com", 1)
        self.statusbar.SetStatusText("By ZQL", 2)

    def OnExit(self, event):
        """Close the frame, terminating the application."""
        self.Close(True)

    def OnClickEnc(self, event):
        key = self.keyText.GetLineText(0)
        plain = ''
        for i in range(self.plainText.GetNumberOfLines()):
            plain += self.plainText.GetLineText(i)
        alg = self.algList[self.algChoice.GetSelection()]
        self.outdataText.AppendText("alg: " + alg + "\n")
        mode = self.modeList[self.modeChoice.GetSelection()]
        self.outdataText.AppendText("mode: " + mode + "\n")
        op = ENC
        iv = self.ivText.GetLineText(0)

        ret, out = SymmCryptoCompute(alg, mode, op, key, iv, plain)
        if ret is False:
            self.outdataText.AppendText("error:\n" + out + '\n')
            # self.statusbar.SetStatusText(out, 1)
            return None

        self.cipherText.Clear()
        self.cipherText.AppendText(str(out))
        self.outdataText.AppendText("加密结果:\n" + str(out) + '\n')

    def OnClickDec(self, event):
        key = self.keyText.GetLineText(0)
        ciphertext = ''
        for i in range(self.cipherText.GetNumberOfLines()):
            ciphertext += self.cipherText.GetLineText(i)
        alg = self.algList[self.algChoice.GetSelection()]
        self.outdataText.AppendText("alg: " + alg + "\n")
        mode = self.modeList[self.modeChoice.GetSelection()]
        self.outdataText.AppendText("mode: " + mode + "\n")
        op = DEC
        iv = self.ivText.GetLineText(0)

        ret, out = SymmCryptoCompute(alg, mode, op, key, iv, ciphertext)
        if ret is False:
            self.outdataText.AppendText("error:\n" + out + '\n')
            return None

        self.plainText.Clear()
        self.plainText.AppendText(str(out))
        self.outdataText.AppendText("解密结果:\n" + str(out) + '\n')


if __name__ == '__main__':
    # When this module is run (not imported) then create the app, the
    # frame, show it, and start the event loop.
    app = wx.App()
    frm = TextFrame(None, title='Hello World 2')
    frm.Show()
    app.MainLoop()
