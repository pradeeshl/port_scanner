from django import forms

class PortScanForm(forms.Form):
    target = forms.CharField(label='Enter Target IP', max_length=100)