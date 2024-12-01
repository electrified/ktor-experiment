package org.maidavale

import io.ktor.server.application.*

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {
    configureHTTP()
//    configureMonitoring()
    configureTemplating()
    configureAdministration()
    configureSerialization()
//    configureDatabases()
    configureSecurity()
    configureRouting()
}
