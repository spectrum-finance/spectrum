ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "3.2.2"

lazy val root = (project in file("."))
  .settings(
    name := "sim",
    libraryDependencies ++= Seq(
      "org.typelevel" %% "cats-effect" % "3.4.6",
      "co.fs2" %% "fs2-core" % "3.5.0",
      "org.typelevel" %% "cats-mtl" % "1.3.0"
    )
  )
