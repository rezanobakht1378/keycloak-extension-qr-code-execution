<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "title">
        ${msg("successQrCodeLoginTitle")}
    <#elseif section = "header">
        ${msg("successQrCodeLoginTitle")}
    <#elseif section = "form">

        <p>${msg("successQrCodeLoginMessage")}<p>
        
    </#if>
</@layout.registrationLayout>
