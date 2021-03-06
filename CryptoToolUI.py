#!/usr/bin/env python3

"""Hello, wxPython! program."""


import wx
from M2Crypto import EVP
from binascii import hexlify, unhexlify
import sys
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT


ENC = 1
DEC = 0
algList = ['aes', 'des', '3des2key', '3des3key', 'sm4']
modeList = ['ecb', 'cbc']


def get_alg_mode(alg, mode, key, iv):
    if alg == 'aes':
        if mode == 'ecb':
            alg_mode = 'aes_128_ecb'
        elif mode == 'cbc':
            alg_mode = 'aes_128_cbc'
            if len(iv) != 32:
                return False, 'iv length must be 16, please input right iv.'
        if len(key) != 32:
            return False, 'key length must be 16, please input right key.'

    elif alg == 'des':
        if mode == 'ecb':
            alg_mode = 'des_ecb'
        elif mode == 'cbc':
            alg_mode = 'des_cbc'
            if len(iv) != 16:
                return False, 'iv length must be 16, please input right iv.'
        if len(key) != 16:
            return False, 'key length must be 8, please input right key.'

    elif alg == '3des2key':
        if mode == 'ecb':
            alg_mode = 'des_ede_ecb'
        elif mode == 'cbc':
            alg_mode = 'des_ede_cbc'
            if len(iv) != 16:
                return False, 'iv length must be 16, please input right iv.'
        if len(key) != 32:
            return False, 'key length must be 16, please input right key.'

    elif alg == '3des3key':
        if mode == 'ecb':
            alg_mode = 'des_ede3_ecb'
        elif mode == 'cbc':
            alg_mode = 'des_ede3_cbc'
            if len(iv) != 16:
                return False, 'iv length must be 16, please input right iv.'
        if len(key) != 48:
            return False, 'key length must be 24, please input right key.'

    return True, alg_mode


def SymmCryptoCompute(alg, mode, op, key, iv, data):
    if alg in ['aes', 'des', '3des2key', '3des3key']:
        ret, alg_mode = get_alg_mode(alg, mode, key, iv)
        if ret == False:
            return ret, alg_mode
        if alg == 'aes':
            if len(data) % 32 != 0:
                return False, 'data length must be 32 * N, please input right data.'
        elif len(data) % 16 != 0:
                return False, 'data length must be 16 * N, please input right data.'
        cipher = EVP.Cipher(alg=alg_mode, key=unhexlify(
            key), iv=unhexlify(iv), op=op, padding=False)
        out = bytes.hex(cipher.update(unhexlify(data)))
        cipher.final()
        return True, str(out)

    elif alg == 'sm4':
        if len(key) != 32:
            return False, 'sm4 key length is 16, please input right key.'
        if len(iv) != 32:
            return False, 'iv length must be 16, please input right iv.'
        if len(data) % 32 != 0:
            return False, 'data length must be 32 * N, please input right data.'
        sm4 = Sm4()

        if op == ENC:
            sm4.sm4_set_key(unhexlify(key), ENCRYPT)
        elif op == DEC:
            sm4.sm4_set_key(unhexlify(key), DECRYPT)

        if mode == 'ecb':
            out = bytes.hex(bytes(sm4.sm4_crypt_ecb(unhexlify(data))))
        elif mode == 'cbc':
            out = bytes.hex(bytes(sm4.sm4_crypt_cbc(unhexlify(iv), unhexlify(data))))
        return True, str(out)


class TextFrame(wx.Frame):

    def __init__(self, *args, **kw):
        wx.Frame.__init__(self, None, -1, 'Crypto Tool',
                          size=(600, 600))
        panel = wx.Panel(self, -1)

        self.statusbar = self.CreateStatusBar()
        self.statusbar.SetFieldsCount(3)
        self.statusbar.SetStatusWidths([-2, -5, -1])
        self.statusbar.SetStatusText("Use wxPython", 0)
        self.statusbar.SetStatusText("zhangqinlei@gmail.com", 1)
        self.statusbar.SetStatusText("By ZQL", 2)

        self.keyLabel = wx.StaticText(panel, -1, "密钥:", pos=[15, 13])
        self.keyText = wx.TextCtrl(panel, -1, "",
                                   size=(250, -1), pos=[55, 10])
        self.keyText.SetInsertionPoint(0)

        self.ivLabel = wx.StaticText(panel, -1, "IV:", pos=[15, 57])
        self.ivText = wx.TextCtrl(panel, -1, "",
                                  size=(250, -1), pos=[55, 55])
        self.keyText.SetInsertionPoint(0)

        self.plainLabel = wx.StaticText(panel, -1, "明文:", pos=[15, 100])
        self.plainText = wx.TextCtrl(panel, -1, "",
                                     size=(250, 150), pos=(55, 100),
                                     style=wx.TE_CHARWRAP | wx.TE_MULTILINE)

        self.cipherLabel = wx.StaticText(panel, -1, "密文:", pos=[15, 283])
        self.cipherText = wx.TextCtrl(panel, -1, "",
                                      size=(250, 150), pos=(55, 280),
                                      style=wx.TE_CHARWRAP | wx.TE_MULTILINE)

        self.algList = ['aes', 'des', '3des2key', '3des3key', 'sm4']
        self.algLabel = wx.StaticText(panel, -1, "算法:", (15, 458))
        self.algChoice = wx.Choice(panel, -1, (50, 455), choices=self.algList)
        self.algChoice.SetSelection(0)

        self.modeList = ['ecb', 'cbc']
        self.modeLabel = wx.StaticText(panel, -1, "模式:", (165, 458))
        self.modeChoice = wx.Choice(panel, -1, (200, 455),
                                    choices=self.modeList)
        self.modeChoice.SetSelection(0)

        self.encButton = wx.Button(panel, -1, "加密", pos=(15, 500))
        self.Bind(wx.EVT_BUTTON, self.OnClickEnc, self.encButton)
        self.encButton.SetDefault()

        self.decButton = wx.Button(panel, -1, "解密", pos=(105, 500))
        self.Bind(wx.EVT_BUTTON, self.OnClickDec, self.decButton)
        self.decButton.SetDefault()

        self.outdataLabel = wx.StaticText(panel, -1, "输出信息:", (325, 12))
        self.outdataText = wx.TextCtrl(panel, -1, "",
                                     size=(250, 390), pos=(325, 40),
                                     style=wx.TE_CHARWRAP | wx.TE_MULTILINE)

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
